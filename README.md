## 프로젝트 개요

### 개발기간

21.12.28(화) ~ 21.01.03(월)
7일간(기획 1일, 개발 6일)

### 전체일정 프로세스
1일차 : 프로젝트 기획(API설계, 와이어프레임작성), 기능 선정, 역할 분담, 기능별 html 제작<br>
2일차 : 로그인 기능 구현, 게시물 작성 기능 구현, 튜터님 피드백, Git과 Github 사용<br>
3일차 : 회원가입 기능 구현, 피드 기능 구현, 마이페이지 기능 구현<br>
4일차 : 피드 기능 개선, 아이디 찾기 기능 구현, 댓글기능 구현<br>
5일차 : 마이페이지 프로필 사진 기능 개선, 로그인·회원가입·마이페이지 css 구현<br>
6일차 : 피드·포스팅 css 구현, 게시물 작성 기능 개선, EC2연결 <br>
7일차 : 댓글기능 개선, ID·Password css 구현, 에러해결, 서비스테스트, 영상제작

## 서비스 기능

### 1. 로그인 페이지
- 회원가입 시 암호화되어 저장된 비밀번호와 로그인 시 받은 비밀번호를 해시함수를 통해 인코딩하여 비교
- DB에 ID와 비밀번호가 일치하는 유저가 있으면 JWT 토근을 받아오는 인증방식으로 구성
- 로그인은 5시간동안 유지되도록 설정
- ID와 비밀번호가 일치하지 않으면 알람창 활성화

### 2. 회원가입 페이지
- ajax의 POST 방식으로 사용자가 회원가입 페이지에서 입력한 정보를 DB에 저장
- 중복확인 기능을 추가하여 DB에 저장된 아이디와 새로운 아이디를 비교하여 중복아이디일 시 알람창 활성화
- 회원가입 시 등록된 이름과 이메일을 데이터베이스에 등록한 정보와 비교하여 알람창으로 아이디를 제공함으로서 아이디 찾기 가능
- 회원가입 시 등록된 아이디와 이메일을 데이터베이스에 등록된 정보와 비교한 후 set연산자 기능을 활용하여 암호화 된 비밀번호 재설정 가능

### 3. 피드 페이지
- 게시물 작성 시 피드 페이지에서 노출
- 댓글 작성 시 각 게시물 하단에서 노출
- 페이지 우측 상단 로그아웃 버튼을 이용하여 로그아웃 가능
- Jinja로 html을 관리하여 공통적으로 적용되는 태그들의 반복 사용을 줄임
- jinja2 템플릿을 활용한 효율적인 통신방식 채택

### 4. 마이 페이지
- 프로필 URL 미설정 시 기본이미지로 설정
- 프로필 URL 설정 시 마이페이지 프로필 이미지와 게시물 작성 시 피드에 노출되는 프로필 이미지 변경
- 게시물 작성자의 ID와 사용자 ID가 일치하는 게시물만 마이페이지에서 노출되게 설정하여, 본인이 작성한 게시물만 마이페이지에서 노출
- 사용자가 작성한 게시물의 수 노출

### 5. 게시물 작성 페이지
- 게시물 작성 후 ajax POST 방식으로 정보를 DB에 저장
- 피드에 작성 시간 import time 으로 작성시간 부여

## 구현기능

  - 로그인 기능
  - 회원가입 및 회원정보 찾기 기능
  - 피드에서 모아보기
  - 댓글 저장 / 삭제 기능
  - 마이페이지 기능
  - 게시물 작성 기능

## 사용도구
- HTML, CSS
- Javascript - Ajax
- Python - pymongo, flask, jwt, datetime, requests
- AWS EC2
- GIT / GIT Hub

## 팀빌딩 및 역할
- 부트캠프 <스파르타 내일배움캠프> 참가자로 구성
- 비전공자 5인의 첫 팀프로젝트
<img width="397" alt="스크린샷 2022-01-04 오전 11 24 18" src="https://user-images.githubusercontent.com/80694130/148001462-dd823e4b-1ed4-4426-95f0-9d61b0c0b71f.png">


### 개발자 (가나다순)
💪 김준형 / aka 헬창 🏋🏼 @[highsky21c](https://github.com/highsky21c)

✔ 로그인 페이지 담당<br>
✔ 회원가입, 회원정보 찾기 기능 구현<br>
✔ 페이지별 기능 오류 수정<br>

🤱 김진주 / aka 주님 🙏 @[kimpearl3599](https://github.com/kimpearl3599)

✔ CSS 구현<br>
✔ 파비콘 & logo 이미지 제작<br>
✔ GIT 사용 및 에러해결<br>

😼 박정훈 / aks 젤리보이 🍡 @[ParkJeonghunn](https://github.com/ParkJeonghunn)

✔ 게시물 페이지 담당<br>
✔ 페이지별 기능 오류 수정<br>
✔ AWS EC2 배포<br>

💊 윤정기 / aka ill_boy 🤓 @[lution88](https://github.com/lution88)

✔ 피드 페이지 담당<br>
✔ 페이지 별 기능 오류 수정<br>
✔ DB 관리<br>

🚴‍♀️ 전승현 / aka pants_ceo👖 @[kidcode](https://github.com/eonsh11)

✔ Pants CEO 인줄 알았으나 Real CEO<br>
✔ 마이 페이지 담당<br>
✔ 페이지별 기능 오류 수정<br>
✔ 댓글 기능 구현<br>

## Spartagram API(https://iridescent-ground-7ce.notion.site/Spartagram-s-API-9b336a12f35f4e63b10f8ef73c293314) 설계하기

![image](https://user-images.githubusercontent.com/79038451/148002043-95df7d6a-316e-42f5-8ff4-f6de55be2e4c.png)
![image](https://user-images.githubusercontent.com/79038451/148002073-e7525c41-b917-4945-be98-8f644cb9364b.png)
![image](https://user-images.githubusercontent.com/79038451/148002093-6fd44f8d-7bd3-4b93-a7ee-dcd0229593d4.png)


## 와이어프레임
### 워크플로우 차트
![](https://images.velog.io/images/gkrwkd95/post/69fa6334-f302-4f69-b7fa-377146504b56/spartagram_wireframe.png)

### 전체 와이어프레임
#### 로그인 페이지
#### 회원가입 페이지
#### 피드 페이지
#### 마이 페이지
#### 게시물 작성 페이지
![](https://user-images.githubusercontent.com/80694130/148000512-401f2b41-8ef3-4b39-8b8d-9e875e48146d.png)

