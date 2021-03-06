from bson import ObjectId
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import certifi
import time

app = Flask(__name__)

from pymongo import MongoClient, collection

ca = certifi.where()
# client = MongoClient('mongodb+srv://test:sparta@cluster0.p2cn0.mongodb.net/Cluster0?retryWrites=true&w=majority')
client = MongoClient('mongodb+srv://test:sparta@cluster0.rtjyu.mongodb.net/Cluster0?retryWrites=true&w=majority',
                     tlsCAFile=ca)
db = client.dbsparta

# JWT 토큰을 만들 때 필요한 비밀문자열입니다. 아무거나 입력해도 괜찮습니다.
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 할 수 있습니다.
SECRET_KEY = 'SPARTA'

# JWT 패키지를 사용합니다. (설치해야할 패키지 이름: PyJWT)
import jwt

# 토큰에 만료시간을 줘야하기 때문에, datetime 모듈도 사용합니다.
import datetime

# 회원가입 시엔, 비밀번호를 암호화하여 DB에 저장해두는 게 좋습니다.
# 그렇지 않으면, 개발자(=나)가 회원들의 비밀번호를 볼 수 있으니까요.^^;
import hashlib


###############################
# token확인 함수
def check_token():
    # 현재 이용자의 컴퓨터에 저장된 cookie 에서 mytoken 을 가져옵니다.
    token_receive = request.cookies.get('mytoken')
    # token을 decode하여 payload를 가져오고, payload 안에 담긴 유저 id를 통해 DB에서 유저의 정보를 가져옵니다.
    payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
    return db.user.find_one({'id': payload['id']}, {'_id': False})


#################################
##  HTML을 주는 부분             ##
#################################
@app.route('/')
def no_way_home():
    return render_template('home.html')


@app.route('/home')
def home():
    # 현재 이용자의 컴퓨터에 저장된 cookie 에서 mytoken 을 가져옵니다.
    token_receive = request.cookies.get('mytoken')
    try:
        # 암호화되어있는 token의 값을 우리가 사용할 수 있도록 디코딩(암호화 풀기)해줍니다!
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": payload['id']})
        return render_template('login.html', id=user_info["id"])
    # 만약 해당 token의 로그인 시간이 만료되었다면, 아래와 같은 코드를 실행합니다.
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        # 만약 해당 token이 올바르게 디코딩되지 않는다면, 아래와 같은 코드를 실행합니다.
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))


@app.route('/login')
def login():
    msg = request.args.get("msg")
    return render_template('login.html', msg=msg)


@app.route('/register')
def register():
    return render_template('register.html')


#################################
##  로그인을 위한 API            ##
#################################

# [회원가입 API]
# id, pw, nickname을 받아서, mongoDB에 저장합니다.
# 저장하기 전에, pw를 sha256 방법(=단방향 암호화. 풀어볼 수 없음)으로 암호화해서 저장합니다.
@app.route('/api/register', methods=['POST'])
def api_register():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    name_receive = request.form['name_give']
    email_receive = request.form['email_give']
    url_receive = request.form['url_give']

    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    db.user.insert_one(
        {'id': id_receive, 'pw': pw_hash, 'name': name_receive, 'email': email_receive, 'url': url_receive})

    return jsonify({'result': 'success'})


#############로그인 중복확인 서버##############################
@app.route('/check_dup', methods=['POST'])
def check_dup():
    userid_receive = request.form['userid_give']
    exists = bool(db.user.find_one({"id": userid_receive}))
    return jsonify({'result': 'success', 'exists': exists})


############################################################


# [로그인 API]
# id, pw를 받아서 맞춰보고, 토큰을 만들어 발급합니다.
@app.route('/api/login', methods=['POST'])
def api_login():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']

    # 회원가입 때와 같은 방법으로 pw를 암호화합니다.
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    # id, 암호화된pw을 가지고 해당 유저를 찾습니다.
    result = db.user.find_one({'id': id_receive, 'pw': pw_hash})

    # 찾으면 JWT 토큰을 만들어 발급합니다.
    if result is not None:
        # JWT 토큰에는, payload와 시크릿키가 필요합니다.
        # 시크릿키가 있어야 토큰을 디코딩(=암호화 풀기)해서 payload 값을 볼 수 있습니다.
        # 아래에선 id와 exp를 담았습니다. 즉, JWT 토큰을 풀면 유저ID 값을 알 수 있습니다.
        # exp에는 만료시간을 넣어줍니다. 만료시간이 지나면, 시크릿키로 토큰을 풀 때 만료되었다고 에러가 납니다.
        payload = {
            'id': id_receive,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1000)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        # token을 줍니다.
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})


# [유저 정보 확인 API]
# 로그인된 유저만 call 할 수 있는 API입니다.
# 유효한 토큰을 줘야 올바른 결과를 얻어갈 수 있습니다.
# (그렇지 않으면 남의 장바구니라든가, 정보를 누구나 볼 수 있겠죠?)
@app.route('/api/user', methods=['GET'])
def api_valid():
    token_receive = request.cookies.get('mytoken')

    # try / catch 문?
    # try 아래를 실행했다가, 에러가 있으면 except 구분으로 가란 얘기입니다.

    try:
        # token을 시크릿키로 디코딩합니다.
        # 보실 수 있도록 payload를 print 해두었습니다. 우리가 로그인 시 넣은 그 payload와 같은 것이 나옵니다.
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])

        # print(payload)에는 회원정보때 입력했던 것들이 들어감

        # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
        # 여기에선 그 예로 닉네임을 보내주겠습니다.
        userinfo = db.user.find_one({'id': payload['id']}, {'_id': 0})
        return jsonify({'result': 'success', 'id': userinfo['id']})
    except jwt.ExpiredSignatureError:
        # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
        return jsonify({'result': 'fail', 'msg': '로그인 시간이 만료되었습니다.'})
    except jwt.exceptions.DecodeError:
        return jsonify({'result': 'fail', 'msg': '로그인 정보가 존재하지 않습니다.'})


#####################정훈님 코드#######################

@app.route('/posting')
def posting():
    return render_template('posting.html')


@app.route('/posting', methods=['POST'])
def posting_post():
    userinfo = check_token()
    user_receive = userinfo['id']
    url_receive = request.form['url_give']
    mylocation_receive = request.form['mylocation_give']
    mytext_receive = request.form['mytext_give']
    # 유저정보에 있는 필드의 마지막 항목은 프로필 url임
    profile_url = list(db.user.find({'id': user_receive}, {'_id': False}))[-1]
    postingtime = time.strftime('%x\n%X', time.localtime(time.time()))


    doc = {
        'id': user_receive,
        # 'num': count,
        'url': url_receive,
        'mylocation': mylocation_receive,
        'mytime': postingtime,
        'mytext': mytext_receive,
        'comments': [{
            'commenter': ''
        }],
        'profile_url': profile_url['url'],
    }

    db.posting.insert_one(doc)

    return jsonify({'msg': '게시글 작성 완료'})


################################################################
################################################################
## 피더부분################


@app.route("/feed_home", methods=["GET"])
def feed_post():
    userinfo = check_token()
    post_id = db.posting.find_one({'id': userinfo['id']})
    all_post = list(db.posting.find({}, {'_id'}))
    posts_info = list(db.posting.find({}))
    comments = list(db.comments.find({}))
    # user_id = db.user.find_one({'id': userinfo['id']})
    return render_template('feed_index.html', post_id=post_id, posts_info=posts_info, comments=comments, all_post=all_post)


@app.route("/feed_com", methods=["POST"])
def comment():
    if request.method == "POST":
        userinfo = check_token()
        real_id = request.form['post_id_give']
        comment_receive = request.form['comment_give']

        doc = {
            'post_id': ObjectId(real_id),
            'commenter': userinfo['id'],
            'reply': comment_receive
        }

        db.comments.insert_one(doc)
        comments_info = list(db.comments.find({'post_id': real_id}, {'_id'}))

        if len(comments_info) != 0:
            db.posting.update_one({'_id': ObjectId(real_id)}, {'$push': {'comments': comments_info.pop()}})
        else:
            print("댓글의 개수가 0입니다.")




        return jsonify({'msg': '성공을 마신다 빠끄'})


@app.route("/feed_home/deletecmt", methods=["POST"])
def cmt_delete():
    userinfo = check_token()
    reply = request.form['cmt_receive']
    # a = list(db.comments.find({}))
    # a['commenter']
    delete_check = db.comments.find_one({'commenter': userinfo['id'], 'reply': reply})

    if delete_check is not None:
        db.comments.delete_one({'commenter': userinfo['id'], 'reply': reply})
        return jsonify({'msg': '댓글 삭제 완료'})
    else:
        return jsonify({'msg': '본인의 댓글이 아닙니다.'})

#####################mypage부분#####################


@app.route("/mypage", methods=["GET", "POST"])
def mypage_post():
    if request.method == "POST":
        # 1번 체크토큰 해준다
        userinfo = check_token()
        url_receive = request.form['img_give']
        empty = ""
        if url_receive is empty:
            url_receive = "https://search.pstatic.net/sunny/?src=https%3A%2F%2Fi1.sndcdn.com%2Favatars-000643159560-6433ap-t500x500.jpg&type=sc960_832"
            return jsonify({'msg': 'url을 입력해 주세요.'})
        elif url_receive is empty:
            url_receive = "https://search.pstatic.net/sunny/?src=https%3A%2F%2Fi1.sndcdn.com%2Favatars-000643159560-6433ap-t500x500.jpg&type=sc960_832"
            return jsonify({'msg': 'url을 입력해 주세요.'})
        # 2번 아이디 받아온다.
        # if url_receive is None:
        # return jsonify({'msg': '이미지 사진 url을 입력해주세요.'})
        # else:
        user_receive = userinfo['id']
        db.user.update_one({'id': user_receive}, {'$set': {'url': url_receive}})
        db.posting.update_many({'id': user_receive}, {"$set": {"profile_url": url_receive}})
        print("post 업데이트 완료")
        # 3번 db에 넣어준다.

        return jsonify({'msg': '사진 업로드 완료'})

    else:
        userinfo = check_token()
        profile = db.user.find_one({'id': userinfo['id']})
        posts = list(db.posting.find({'id': userinfo['id']}, {'_id': False}))

        return render_template('mypage.html', user=userinfo, profile=profile, posts=posts, id=userinfo['id'])


################################################################
################################################################
################################################################
##################아이디 찾기########################


@app.route('/api/findid', methods=['POST'])
def find_id_email():
    username_receive = request.form['username_give']
    useremail_receive = request.form['useremail_give']
    user_info = db.user.find_one({'name': username_receive, 'email': useremail_receive}, {'_id': False})
    if user_info is not None:
        return jsonify({'result': 'success', 'id': user_info['id']})
    else:
        return jsonify({'msg': '입력하신 정보와 일치하는 사용자가 없습니다.'})


##오브젝트 아이디값 같이 안넘어가게 하자###
#################################################
#################################################
#################################################
#######비밀번호 재설정###########################


@app.route('/password_reset')
def password_reset_page():
    return render_template('password_reset.html')


@app.route('/api/password_reset', methods=['POST'])
def password_reset():
    userid_receive = request.form['userid_give']
    useremail_receive = request.form['useremail_give']
    pw_receive = request.form['pw_give']
    user_info = db.user.find_one({'id': userid_receive, 'email': useremail_receive}, {'_id': False})
    if user_info is not None:
        pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()
        db.user.update_one({'id': userid_receive, 'email': useremail_receive}, {'$set': {'pw': pw_hash}})
        return jsonify({'msg': '비밀번호 재설정이 완료되었습니다.'})
    else:
        return jsonify({'msg': '입력하신 정보와 일치하는 사용자가 없습니다.'})


##################아이디 찾기 페이지#####################
#####################################################
#####################################################


@app.route('/find')
def find_id():
    return render_template('find_ID_Password.html')


#####################################################


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
