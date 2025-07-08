from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length, Email
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import argparse
import io
import time

import torch

from flask import Flask, request, render_template, jsonify, send_file, make_response, Response, session
from PIL import Image
from entity import ResponseBase
import numpy as np
import cv2
from flask_cors import CORS
import base64
import threading
import hashlib
import random
import os
from werkzeug.utils import secure_filename

db = SQLAlchemy()
app = Flask(__name__)
app.config['SECRET_KEY'] = "2b2b49df2ff06d47dbf229ac052023f6"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root:root@127.0.0.1:3306/viewer?charset=utf8"
app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
db.init_app(app)


login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
CORS(app, supports_credentials=True)  # 在应用中启用 CORS
app.secret_key = 'hhk'  # 设置一个用于加密会话的密钥
models = {}
DETECTION_URL = '/v1/object-detection/<model>'

# 将默认模型设置为 'yolov5s'
DEFAULT_MODEL = 'yolov5s'

# app.register_blueprint(test_api)

# is_open_camera = False
camera = None
camera_post = None
pre_camera = None

# cam_ret, cam_frame = False, None

UPLOAD_FOLDER = 'static/video/user_undealed'
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Register, int(user_id))


class Register(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(100))
    password = db.Column(db.String(200))
    rank =db.Column(db.String(100))
    
    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_active(self):
        return True

    def get_id(self):
        return str(self.id)

    def is_authenticated(self):
        return True

class Images(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), index=True)
    image = db.Column(db.LargeBinary(length=65536))
class Viedos(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), index=True)
    video = db.Column(db.LargeBinary(length=262144))
class MeetingHelpRequired(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), index=True)
    roomid= db.Column(db.String(100), index=True)

with app.app_context():
    db.create_all()


class RegistrationForm(FlaskForm):
    email = EmailField(label='电子邮箱', validators=[DataRequired(), Email()])
    name = StringField(label="姓名", validators=[DataRequired(), Length(min=2, max=100)])
    username = StringField(label="用户名", validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField(label="密码", validators=[DataRequired(), Length(min=8, max=20)])
    rank = StringField(label="视力等级", validators=[DataRequired(), Length(min=1, max=100)])

class LoginForm(FlaskForm):
    email = EmailField(label='电子邮箱', validators=[DataRequired(), Email()])
    password = PasswordField(label="密码", validators=[DataRequired()])

@app.route("/")
def home(): 
    return render_template("home.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = Register.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("登录成功！", "success")
            next_page = session.pop('next', None)
            return redirect(next_page or url_for("home"))
        else:
            flash("邮箱或密码错误，请重试。", "error")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("您已成功登出！", "info")
    return redirect(url_for("home"))


@app.route("/register", methods=["POST", "GET"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = RegistrationForm()
    if request.method == "POST":
        existing_user = Register.query.filter_by(email=form.email.data).first()
        existing_username = Register.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("该电子邮箱已被注册，请直接登录或使用其他邮箱。", "danger")
        elif existing_username:
            flash("该用户名已被使用，请选择其他用户名。", "danger")
        elif form.validate():
            new_user = Register(
                email=form.email.data,
                name=form.name.data,
                username=form.username.data,
                rank=form.rank.data
            )
            new_user.set_password(form.password.data)
            try:
                db.session.add(new_user)
                db.session.commit()
                flash("账户创建成功！您现在可以登录了。", "success")
                return redirect(url_for("login"))
            except IntegrityError:
                db.session.rollback()
                flash("注册过程中发生错误，请重试。", "danger")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{getattr(form, field).label.text}: {error}", "danger")
    return render_template("register.html", form=form)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", name=current_user.name)


@app.route("/meeting")
@login_required
def meeting():
    return render_template("meeting.html", username=current_user.username)


@app.route("/join", methods=["GET", "POST"])
@login_required
def join():
    if request.method == "POST":
        room_id = request.form.get("roomID")
        print(current_user.email)
        return redirect(f"/meeting?roomID={room_id}")
    return render_template("join.html")

@app.route("/upRoom_id", methods=["GET","POST"])
@login_required
def upRoom_id():
    if request.method == "POST":      
        data = request.get_json()  # 获取请求体中的 JSON 数据
        upRoom_id = data.get("upRoom_id")
        #将需帮助会议号存入数据库
        try:
            print(current_user.email)
            print(upRoom_id)
            #存入数据库
            upRoom_id_save=MeetingHelpRequired(email=current_user.email,roomid=upRoom_id)
            db.session.add(upRoom_id_save)
            db.session.commit()

            return ResponseBase.success('传递会议号成功',upRoom_id)
        except Exception as e:
            db.session.rollback()
            return str(e), 500

@app.route("/meeting_volunteer_service")
@login_required
def meeting_volunteer_service():
    # 查询所有会议号    
    session = db.session()  
    roomid_result = session.query(MeetingHelpRequired.email,MeetingHelpRequired.roomid).all()  
    session.close() 
    
    roomid_data = [{'email': row[0], 'roomid': row[1]} for row in roomid_result]  
    print(roomid_data)
 
    return render_template("meeting_volunteer_service.html", roomids=roomid_data)

@app.route("/finish_meeting_service", methods=["GET","POST"])
@login_required
def finish_meeting_service():
    if request.method == 'POST':
        roomid_delete = request.form['roomid']
        deleted = MeetingHelpRequired.query.filter_by(roomid=roomid_delete).first()
        if deleted:
            db.session.delete(deleted)
            db.session.commit()
        else:
            flash("输入房间号错误，请重试。", "error")
                    
    return redirect(url_for("meeting_volunteer_service")) 
        

@app.route("/object_detection")
@login_required
def object_detection():
    return render_template("object_detection.html")

@app.route('/')
@app.route('/index')
def go_index():
    return render_template('index.html')


# 定义404错误处理器
@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.route('/uploadImg', methods=['POST'])
def upload_img():
    
    if request.method != 'POST':
        return
    print(request.files)
    if 'file' not in request.files:
        return 'Not a file'
    img = request.files['file']
    if img.filename == '':
        return ResponseBase.error('上传失败')
    # 保存用户上传的图片
    # img.save('static/img/user_undealed/' + img.filename)       

    return ResponseBase.success('上传成功', img.filename)


@app.route('/uploadVideo', methods=['POST'])
def upload_video():
    if 'file' not in request.files:
        return ResponseBase.error('没有文件部分')
    file = request.files['file']
    if file.filename == '':
        return ResponseBase.error('没有选择文件')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        return ResponseBase.success('文件上传成功', {'filename': filename})
    return ResponseBase.error('不允许的文件类型')


@app.route('/uploadVideo1', methods=['POST'])
def upload_video1():
    if request.method != 'POST':
        return
    print(request.files)
    if 'file' not in request.files:
        return 'Not a file'
    video = request.files['file']
    if video.filename == '':
        return ResponseBase.error('上传失败')
    # 保存上传的文件到服务器---确保存在改文件路径
    randrom_str = hashlib.md5(str(random.random()).encode()).hexdigest()
    file_path = f'static/video/user_undealed/{randrom_str}.mp4'
    video.save(file_path)
    # 保存用户上传的视频
    session['upload_video_path'] = file_path
    # 保存用户上传的图片
    # img.save('static/img/user_undealed/' + img.filename)
    return ResponseBase.success('上传成功', video.filename)


@app.route('/start_predict/<model>', methods=['POST'])
def start_predict(model):
    if request.method != 'POST':
        return
    try:
        # 获取上传的文件
        if 'image' not in request.files:
            return 'No image provided', 400
        # print(request.files)
        # image_file.save('static/img/user_undealed/' + image_file.filename)
        # 保存上传的图片文件，或者进行其他处理
        # image_file.save('path_to_save/' + image_file.filename)
        image_file = request.files['image']
        im_bytes = image_file.read()
        im = Image.open(io.BytesIO(im_bytes))
        if model in models:
            results = models[model](im)  # reduce size=320 for faster inference
            # return results.pandas().xyxy[0].to_json(orient='records')
            # 使用 Matplotlib 将 numpy 数组转换为图像
            image_array = results.render()[0]
            show_img = Image.fromarray(image_array, mode='RGB')
            # 将图像数据保存到内存中的二进制对象
            buffer = io.BytesIO()
            show_img.save(buffer, format='jpeg')
            # 获取字节流数据
            buffer.seek(0)
            return send_file(buffer, mimetype='image/jpeg')
            # return ResponseBase.success('预测成功', results.pandas().xyxy[0].to_json(orient='records'))
        else:
            response = make_response(jsonify(msg='OK'))
            response.status_code = 400  # 设置响应的状态码为 200 OK
            return response
    except Exception as e:
        return str(e), 500


@app.route('/start_video_predict', methods=['POST'])
def start_video_predict():
    data = request.json
    filename = data.get('filename')
    if not filename or not isinstance(filename, str):
        return ResponseBase.error('没有提供有效的文件名')

    input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    output_path = os.path.join('static/video/user_dealed', f'processed_{filename}')

    try:
        cap = cv2.VideoCapture(input_path)
        if not cap.isOpened():
            return ResponseBase.error('无法打开视频文件')

        # 获取视频属性
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = int(cap.get(cv2.CAP_PROP_FPS))

        # 创建VideoWriter对象
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))

        while True:
            ret, frame = cap.read()
            if not ret:
                break

            # 使用YOLOv5模型进行预测
            results = models[DEFAULT_MODEL](frame)

            # 在帧上绘制预测结果
            annotated_frame = results.render()[0]

            # 写入处理后的帧
            out.write(annotated_frame)

        cap.release()
        out.release()

        return ResponseBase.success('视频处理完成',
                                    {'processed_video': f'/static/video/user_dealed/processed_{filename}'})
    except Exception as e:
        print(f"处理视频时发生错误: {str(e)}")
        return ResponseBase.error('处理视频时发生错误'), 500


@app.route('/start_img_predict', methods=['POST'])
def start_img_predict():
    if request.method != 'POST':
        return
    try:
        # 获取上传的文件
        if 'image' not in request.files:
            return 'No image provided', 400
        image_file = request.files['image']
        im_bytes = image_file.read()
        im = Image.open(io.BytesIO(im_bytes))
        
        #存入数据库
        image_file_save=Images(email=current_user.email,image=im_bytes)
        db.session.add(image_file_save)
        db.session.commit()

        # 使用默认模型
        results = models[DEFAULT_MODEL](im)
        image_array = results.render()[0]
        show_img = Image.fromarray(image_array, mode='RGB')

        # 保存图像到指定路径
        randrom_str = hashlib.md5(str(random.random()).encode()).hexdigest()
        save_path = f'static/img/user_dealed/{randrom_str}.jpg'
        show_img.save(save_path)
        return_path = 'http://127.0.0.1:5000/' + save_path

        return ResponseBase.success('检测成功!', return_path)
    except Exception as e:
        db.session.rollback()
        return str(e), 500


# 开始摄像头检测
@app.route('/start_camera_predict', methods=['POST'])
def start_camera_predict():
    global camera
    camera = cv2.VideoCapture(0)  # 使用默认摄像头
    if not camera.isOpened():
        print("无法打开摄像头")
        return ResponseBase.error('无法打开摄像头!')
    else:
        return ResponseBase.success_msg('正常开始检测!')


# 获取检测结果
@app.route('/get_camera_det_result')
def get_camera_det_result():
    return Response(gen_det_frame(), mimetype='multipart/x-mixed-replace;boundary=frame')


@app.route(DETECTION_URL, methods=['POST'])
def predict(model):
    if request.method != 'POST':
        return

    if request.files.get('image'):
        # Method 1
        # with request.files["image"] as f:
        #     im = Image.open(io.BytesIO(f.read()))

        # Method 2
        im_file = request.files['image']
        im_bytes = im_file.read()
        im = Image.open(io.BytesIO(im_bytes))

        if model in models:
            results = models[model](im, size=640)  # reduce size=320 for faster inference
            return results.pandas().xyxy[0].to_json(orient='records')


# 捕获摄像头
# camera = cv2.VideoCapture(0)
# camera = cv2.VideoCapture(0)
# camera = ''
# flag = 0
# camera = cv2.VideoCapture(0)
# 不断的生成摄像头捕获的实时画面
def gen_frame():
    # if not flag:
    #     return
    # global camera
    # if
    global camera
    while True:
        ret, frame = camera.read()
        if not ret:
            break
        else:
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type:image/jpeg\r\n\r\n' + frame + b'\r\n')  # concat frame one by one and show result


# 获取实时摄像头检测数据
def gen_det_frame():
    global camera
    while True:
        ret, frame = camera.read()
        if not ret:
            break
        else:
            processed_frame = models[DEFAULT_MODEL](frame)
            frame = processed_frame.render()[0]
            ret, buffer = cv2.imencode('.jpg', frame)
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type:image/jpeg\r\n\r\n' + frame + b'\r\n')  # concat frame one by one and show result


@app.route('/video_start', methods=['GET'])
def video_start():
    return Response(gen_frame(), mimetype='multipart/x-mixed-replace;boundary=frame')


# 事实展示检测图像
@app.route('/video_det_start', methods=['GET'])
def video_det_start():
    return Response(gen_det_frame(DEFAULT_MODEL), mimetype='multipart/x-mixed-replace;boundary=frame')


# 已废弃不使用
def open_camera2(device):
    print(device)
    # 尝试打开摄像头
    if device == 'haikang':
        rtsp_path = "rtsp://admin:wqj12345678@192.168.1.64/Streaming/Channels/2"
    elif device == 'phone':
        rtsp_path = "http://10.0.10.74:4747/video"
    else:
        rtsp_path = 0
    global camera
    camera = cv2.VideoCapture(rtsp_path)
    if not camera.isOpened():
        print("无法打开摄像头。")
        return None
    return camera


@app.route('/open_camera/<device>', methods=['POST'])
def open_camera(device, camera_index=0):
    global camera
    camera = open_camera2(device)
    # print(camera is None)
    # flag = 1  frame too many
    # 检查摄像头是否成功打开
    if not camera:
        print("无法打开摄像头。")
        return ResponseBase.error('打开失败')
    # return Response(gen_frame(), mimetype='multipart/x-mixed-replace;boundary=frame')

    return ResponseBase.success_msg(msg='打开成功')


# 调用打开摄像头函数

# open_camera()
@app.route('/close_camera', methods=['POST'])
def close_camera():
    # 释放摄像头资源并关闭窗口
    global camera
    try:
        camera.release()
        camera = None
        cv2.destroyAllWindows()
        return ResponseBase.success_msg('关闭成功!')
    except Exception as e:
        print("发生异常:", e)
        # return ResponseBase.error('还未打开摄像头!')
        return ResponseBase.error('还未打开摄像头!'), 500




@app.route("/visual_question_answering", methods=["GET", "POST"])
def visual_question_answering():
    gradio_url = "https://43.155.248.134:7860/"  # 替换为你的 Gradio 公网 URL
    return render_template('visual_question_answering.html', gradio_url=gradio_url)


@app.before_request
def before_request():
    if not current_user.is_authenticated:
        if request.endpoint in ['meeting', 'join', 'object_detection','index','404', 'visual_question_answering']:
            session['next'] = request.url
            flash("请先登录以访问此页面。", "info")
            return redirect(url_for('login'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flask API exposing YOLOv5 model')
    parser.add_argument('--port', default=5000, type=int, help='port number')
    opt = parser.parse_args()

    # 加载默认模型
    models[DEFAULT_MODEL] = torch.hub.load('./', DEFAULT_MODEL, source='local')

    # 设置模型的类别名称为中文
    models[DEFAULT_MODEL].names = [
        "人", "自行车", "汽车", "摩托车", "飞机", "公交车", "火车", "卡车", "船", "红绿灯",
        "消防栓", "停车标志", "停车计时器", "长椅", "鸟", "猫", "狗", "马", "羊", "牛",
        "大象", "熊", "斑马", "长颈鹿", "背包", "雨伞", "手提包", "领带", "行李箱", "飞盘",
        "滑雪板", "单板滑雪", "球", "风筝", "棒球棒", "棒球手套", "滑板", "冲浪板", "网球拍", "瓶子",
        "酒杯", "杯子", "叉子", "刀", "勺子", "碗", "香蕉", "苹果", "三明治", "橙子",
        "西兰花", "胡萝卜", "热狗", "披萨", "甜甜圈", "蛋糕", "椅子", "沙发", "盆栽", "床",
        "餐桌", "马桶", "电视", "笔记本电脑", "鼠标", "遥控器", "键盘", "手机", "微波炉", "烤箱",
        "烤面包机", "水槽", "冰箱", "书", "时钟", "花瓶", "剪刀", "泰迪熊", "吹风机", "牙刷"
    ]

    app.run(host='0.0.0.0', port=opt.port, debug=True)


if __name__ == "__main__":
    app.run(debug=True)
