from flask import Flask, render_template, Response, request, Markup, flash, send_file, url_for,  session, redirect
from flask_socketio import SocketIO, emit
# from camera import VideoCamera
import urllib
import socket
serverIP = socket.gethostbyname(socket.gethostname())
app = Flask(__name__)
socketio = SocketIO(app)
if __name__ == '__main__':
    app.run(host=serverIP, port="80", debug=True)
