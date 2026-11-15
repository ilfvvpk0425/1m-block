# 1m-block

100만 개 도메인 목록에 있는 사이트로 가는 HTTP / HTTPS 연결을 Linux netfilter(NFQUEUE)에서 끊는 차단기.

2021년 네트워크 보안 과제로 만든 `1m-block`(첫 커밋 `d52ecd5`)을 다시 작성했다. 목표는 세 가지였다.

1. 예전 코드의 버그를 고친다.
2. 100만 개 목록을 실제로 감당할 만큼 빠르게 만든다.
3. 실제 트래픽에서 생기는 우회 경로를 찾아서 막는다.

## 2021 버전의 문제

| 문제 | 결과 |
|---|---|
| `is_block()` 루프에서 `cnt`를 증가시키지 않음 | 첫 패킷부터 **무한 루프** |
| 전역 `blocked`를 1로 만든 뒤 되돌리지 않음 (`blocked--`가 `return` 뒤에 있음) | 한 번 걸리면 이후 **모든 패킷 drop** |
| 패킷마다 100만 개를 `strncmp`로 선형 탐색 | 측정해 보니 조회 1번에 약 2.2ms (아래 표) |
| TCP 헤더 20바이트, `"GET / HTTP/1.1\r\nHost: "` 위치를 고정값으로 가정 | TCP 옵션이 있거나 경로·헤더 순서가 다르면 엉뚱한 곳을 읽음. 길이 검사도 없음 |
| `fopen`·`fscanf` 결과 미확인, 100바이트 버퍼에 `%s` | 파일이 없으면 크래시, 긴 줄이면 오버플로 |
| HTTPS 미지원 | TLS 트래픽은 전부 통과 |

## 구조

```
src/domainset.c  도메인 해시셋 (문자열 arena + 오픈 어드레싱), 라벨 단위 서브도메인 매칭
src/sniff.c      IPv4/IPv6 + TCP -> HTTP Host / TLS ClientHello SNI 추출, 모든 접근 범위 검사
src/engine.c     패킷 하나의 판정. 여러 세그먼트로 나뉜 요청·ClientHello 재조립, 차단된 연결 기억
src/main.c       NFQUEUE 루프, 로그, 통계, 옵션
tests/test.c     단위 테스트 + fuzz (ASan/UBSan)
scripts/e2e.sh   실제 NFQUEUE 규칙으로 하는 종단 테스트 (127.0.0.1 안에서만)
scripts/load.sh  iperf3로 큐 처리량 측정
bench/bench.c    조회·파싱 마이크로벤치마크
```

- **매칭 규칙**: 목록에 `example.com`이 있으면 `example.com`과 `www.example.com`은 막고, `xexample.com`이나 `example.com.evil.org`는 막지 않는다. `-x` 옵션을 주면 정확히 같은 이름만 막는다.
- **정규화**: 대소문자, 끝의 점, `Host:` 헤더의 `:port`를 정규화한다.

## 사용법

```bash
sudo apt install build-essential libnetfilter-queue-dev iptables
make && make test

# 1) 가장 단순한 형태: 웹 트래픽 전부를 큐로
sudo iptables -I OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 0 --queue-bypass
sudo ./1m-block top-1m.csv
```

**권장 구성**은 각 연결의 처음 10패킷만 큐로 보내고, 차단한 연결은 커널이 기억해서 끊는 방식이다. 이유는 아래 [성능](#성능)과 [찾아낸 우회와 대응](#찾아낸-우회와-대응)에 있다.

```bash
P="-p tcp -m multiport --dports 80,443"
sudo iptables -A OUTPUT $P -m connmark --mark 0x1/0x1 -j DROP
sudo iptables -A OUTPUT $P -m mark --mark 0x1/0x1 -j CONNMARK --save-mark --nfmask 0x1 --ctmask 0x1
sudo iptables -A OUTPUT $P -m mark --mark 0x1/0x1 -j DROP
sudo iptables -A OUTPUT $P -m connbytes --connbytes 0:10 --connbytes-dir original --connbytes-mode packets \
     -j NFQUEUE --queue-num 0 --queue-bypass
sudo ./1m-block -M 0x1 top-1m.csv
```

| 옵션 | 의미 |
|---|---|
| `-q N` | 큐 번호 |
| `-x` | 정확히 일치하는 이름만 차단 |
| `-n` | 모니터 모드: 기록만 하고 통과시킴 |
| `-v` | 통과한 호스트도 기록 |
| `-M m` | 차단 패킷에 mark를 붙여 커널에서 끊게 함 (`NF_REPEAT`) |

`--queue-bypass`와 fail-open 설정 덕분에, 차단기가 꺼져 있거나 처리가 밀리면 트래픽은 막히지 않고 통과한다.

Ctrl+C로 끄면 처리한 패킷 수, 호스트를 찾은 패킷 수, 차단 수, 재조립 횟수를 출력한다. 차단 로그는 같은 호스트에 대해 5초에 한 번만 남긴다. 버린 패킷은 TCP가 여러 번 재전송하기 때문이다.

## 테스트

**단위 테스트** (`make test`, AddressSanitizer + UBSan): 50,083개 검사, 실패 0.
- 해시셋: 대소문자·끝 점·중복, 라벨 경계, 5만 개 삽입 후 전체 조회, CSV·주석·CRLF·2,000자 줄 읽기
- 파서
  - Host 헤더 변형: `hOsT:`, `:port`, LF만 쓰는 줄바꿈, `X-Host`와 혼동하지 않는지, 본문의 `Host:`는 무시하는지, IPv6 리터럴
  - TCP 옵션, IPv6, UDP, IP 단편
  - ClientHello를 모든 길이로 잘라 보기, 길이 필드 조작
- fuzz: 정상 패킷을 무작위로 변형·절단한 입력 30만 회
- 엔진: 분할 ClientHello, 재전송, 시퀀스 번호 wrap-around, 두 연결이 끼어드는 경우, 중간 세그먼트 누락, 항목 만료, 헤더가 끝없이 이어지는 경우, 테이블 초과, 무작위 세그먼트 20만 회

**종단 테스트** (`sudo scripts/e2e.sh`): WSL2 Ubuntu 24.04 (커널 6.6.87)에서 실행했다.
- 127.0.0.1에 HTTP 서버와 TLS 서버를 띄우고, curl과 직접 만든 TLS 클라이언트(`scripts/split_hello.py`)로 요청한다.
- 규칙은 루프백의 테스트 포트에만 걸고, 끝나면 지운다.

| 구성 | 결과 |
|---|---|
| 모든 패킷 큐 | 18 / 18 통과 |
| `CONNBYTES=1` (첫 10패킷만 큐) | 18 / 18 통과 |
| `CONNBYTES=1 LONG=1` | 18 / 19 — **45초 대기 항목 실패 (아래 우회 2)** |
| `CONNBYTES=1 MARK=1 LONG=1` | 19 / 19 통과 |
| `MARK=1` | 18 / 18 통과 |

e2e가 확인하는 항목:
- 허용 도메인 → 200
- 차단 도메인과 그 서브도메인 → 응답 없음
- 이름이 비슷한 다른 도메인(`notblocked.test`, `ads.example.org`) → 200
- 한 세그먼트·두 세그먼트 ClientHello
- 차단기를 끄면 통과하는지(fail-open)
- 로그 내용

## 성능

측정 환경: i5-12400F, WSL2, Tranco top-1M 목록(list id `947V2`, 2026-11-14), 각 3회 측정. 원본 출력은 `bench/micro_raw.txt`, `bench/load_raw.txt`에 있다.

**조회와 파싱** (`make bench && ./build-bench top-1m.csv`)

| 항목 | 결과 |
|---|---|
| 100만 개 로딩 | 0.196 ~ 0.203초, 해시셋 48 MiB (테이블 32 + 문자열 16) |
| 해시셋 조회, 정확히 일치 | 129 ~ 132 ns |
| 해시셋 조회, 서브도메인 포함 | 223 ~ 225 ns |
| 2021 방식 선형 탐색 (목록에 없는 이름) | 2.17 ~ 2.24 ms → **약 17,000배 느림** |
| 파싱: HTTP GET 234B / ClientHello 552B / 기타 1,240B | 67 ~ 69 / 21 / 6 ns |

**NFQUEUE 처리량** (`sudo scripts/load.sh top-1m.csv`)
- iperf3로 루프백 TCP, MSS 1460으로 측정했다.
- 페이로드는 무작위 데이터라서 조회는 거의 일어나지 않는다. 즉 "큐를 거치는 비용"을 재는 측정이다.

| 구성 | 처리량 |
|---|---|
| 규칙 없음 | 65.2 ~ 66.0 Gbit/s |
| 모든 패킷 큐 + 1m-block | 3.00 ~ 3.04 Gbit/s (약 26만 패킷/초) |
| 모든 패킷 큐 + 모니터 모드 | 3.02 ~ 3.07 Gbit/s |
| 첫 10패킷만 큐 + 1m-block | **61.4 ~ 61.9 Gbit/s** |

해석:
- 패킷당 파싱+조회는 수십~수백 ns인데, 모든 패킷을 큐로 보내면 패킷당 약 3.8µs가 든다. 병목은 조회가 아니라 **커널↔사용자 공간 복사와 판정 왕복**이다.
- Host와 SNI는 연결의 처음 몇 패킷에만 있으므로 `connbytes`로 앞부분만 보내면 된다. 이 테스트에서 8초 동안 큐를 거친 패킷은 약 2백만 개에서 60여 개로 줄었다.
- 재조립 기능을 처음 넣었을 때 처리량이 3.1 → 2.5 Gbit/s로 떨어졌다. 데이터 패킷마다 흐름 테이블 전체(256칸)를 훑었기 때문이다. 해시 위치부터 16칸만 보도록 바꿔 원래 수준으로 되돌렸다(커밋 `6b5dee9`).

## 찾아낸 우회와 대응

### 1. ClientHello가 두 세그먼트로 나뉘면 SNI를 못 본다

- **재현**: `split_hello.py`로 ClientHello를 SNI 확장 바로 앞에서 둘로 나눠 보냈다. 처음 만든 버전은 첫 세그먼트에서 SNI를 찾지 못했고, 두 번째 세그먼트는 TLS 레코드로 시작하지 않아서 둘 다 통과시켰다. 결과는 `blocked.test` → **200**이었다.
- **의미**: 최근 브라우저는 양자내성 하이브리드 키 공유를 쓰면서 ClientHello가 MSS보다 커지는 경우가 많다고 알려져 있다. 이 실험은 클라이언트가 직접 나눈 경우만 재현한 것이고, 실제 브라우저 트래픽으로는 확인하지 않았다.
- **대응** (`engine.c`)
  - 파서가 "요청이나 레코드는 시작됐는데 호스트가 아직 안 보인다"(`SNIFF_MORE`)를 알려 주면, 연결별로 앞부분을 최대 8KB, 8세그먼트까지 모은다.
  - TCP 시퀀스 번호로 다음 세그먼트를 이어 붙인다.
  - 차단으로 판정한 연결은 기억해서 재전송을 포함해 데이터 패킷을 계속 버린다.
  - HTTP 헤더가 나뉘어 Host가 뒤 세그먼트에 있는 경우도 같은 방법으로 처리한다.

### 2. 앞부분만 큐로 보내면, 재전송이 10개를 넘긴 뒤 통과한다

- **재현**: `connbytes 0:10` 규칙에서 차단 대상에 요청하고 90초를 기다렸다. 결과는 **26.8초 뒤 200**이었다.
- **원인**: 차단기는 판정한 패킷만 버린다. 클라이언트의 재전송도 conntrack의 패킷 수에 들어가므로, 10번째 이후 재전송은 큐를 거치지 않고 통과한다.
- **대응** (`-M`)
  - 차단할 패킷에 mark를 붙이고 `NF_REPEAT`으로 체인을 다시 타게 한다.
  - iptables가 그 mark를 conntrack에 저장(`CONNMARK --save-mark`)하고 패킷을 버린다.
  - 이후 그 연결의 모든 패킷은 첫 번째 규칙(`connmark` → DROP)에서 커널이 바로 버린다. 대응 후 45초 대기 테스트에서 응답이 없었다(000).
  - mark 규칙 없이 `-M`만 켜면 표시된 패킷이 큐로 다시 돌아온다. 이때는 그냥 버려서 무한 루프를 막는다. 이 경우도 따로 확인했다.

## 한계

- **ECH (Encrypted Client Hello)**: 보이는 SNI는 바깥쪽(CDN 등)의 이름뿐이라, 실제 목적지 기준으로는 막을 수 없다.
- **QUIC / HTTP/3 (UDP 443)**: 처리하지 않는다. TCP만 본다. 대개는 UDP 443을 막아서 TCP로 되돌아가게 하는 방식으로 운영한다.
- **keep-alive의 두 번째 요청**: `connbytes`를 쓰면 같은 HTTP 연결에서 나중에 다른 Host로 보내는 요청은 보지 못한다. 모든 패킷을 큐로 보내면 본다.
- **TLS 레코드 여러 개에 걸친 ClientHello**: 레코드 하나 안에서 나뉜 경우만 재조립한다.
- **테스트 범위**: 루프백(OUTPUT 체인)에서만 테스트했다. 게이트웨이(FORWARD 체인)나 실제 브라우저 트래픽, IPv6 종단 테스트는 하지 않았다(IPv6는 단위 테스트만).
- **단일 스레드**: 모든 패킷을 큐로 보내면 이 환경에서 약 26만 패킷/초가 한계다.

## 다음에 해 볼 것

- VMware VM을 클라이언트로 두고 FORWARD 체인 게이트웨이로 실제 브라우저 트래픽 시험
- `--queue-balance` + 다중 스레드, `nfq_set_verdict_batch`로 판정 묶어 보내기
- QUIC Initial 패킷 복호화로 HTTP/3 SNI 추출
