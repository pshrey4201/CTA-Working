from flask import Flask, render_template, Response, request, Markup, flash
from camera import VideoCamera
import os
from werkzeug import secure_filename
from flask_socketio import SocketIO
import urllib
import time
import datetime
import json
import requests
import socket
import gspread
from oauth2client.service_account import ServiceAccountCredentials

scope = ['https://spreadsheets.google.com/feeds',
         'https://www.googleapis.com/auth/drive']
creds = ServiceAccountCredentials.from_json_keyfile_name('client_secret.json', scope)

serverIP = socket.gethostbyname(socket.gethostname())
reportUrl = 'https://www.virustotal.com/vtapi/v2/file/report'
scanUrl = 'https://www.virustotal.com/vtapi/v2/file/scan'
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
apikey = '53074e57c64d3b33a36d8bd638319b23295b20be787922febe3e6c6bc8f5ca1c'
socketio = SocketIO(app)
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/users')
def users():
    client = gspread.authorize(creds)   
    q = 0
    counter = 0
    oldmin = 0
    oldhour = 0
    oldsec = 0
    dayCounter = 0
    # jsdata = request.form['javascript_data']
    # print(ipadd)
    # print(jsdata)
    ip = request.args.get('ip')
    ipIsThere = False
    for spreadsheet in client.openall():
        # print(spreadsheet.title)
        # titles_list.append(spreadsheet.title)
        if spreadsheet.title == ip:
        # #     # print(spreadsheet.title + " " + spreadsheet.id)
            # client.del_spreadsheet(spreadsheet.id)
            sh = client.open(ip)
            ipIsThere = True
            for s in sh.worksheets():
                sheet = sh.get_worksheet(q)
                day = sheet.cell(1,2).value
                month = sheet.cell(1,3).value
                year = sheet.cell(1,4).value
                h = sheet.cell(1,5).value
                m = sheet.cell(1,6).value
                s = sheet.cell(1,7).value
                if int(datetime.datetime.now().strftime("%m")) - int(month) <= 1 and int(datetime.datetime.now().strftime("%d")) - int(day) <= 1 and int(datetime.datetime.now().strftime("%H")) - int(h) <= 24:
                    counter += 1
                    if int(datetime.datetime.now().strftime("%d")) - int(day) <= 1 and int(datetime.datetime.now().strftime("%H")) - int(h) <= 24:
                        dayCounter += 1
                    # print(counter)
                    # print(oldhour)
                    if int(h) >= oldhour and int(m) >= oldmin:
                        # print(m)
                        oldmin = int(m)
                        oldhour = int(h)
                        name = sheet.cell(1,1).value
                        link = sheet.cell(1,8).value
                        detected = sheet.cell(1,9).value
                        total = sheet.cell(1,10).value
                        # print(oldmin)
                q += 1
            message = Markup("<li>User Statistics</li><li>Number of File Scanned in the Past 24 Hours: " + str(dayCounter) + "</li><li>Number of Files Scanned in the Past Month: " + str(counter) + "</li><li>Last File Scanned: " + name + "</li><li>Number of Antiviruses used: " + total + "</li><li>Number of Antiviruses detecting Virus: " + detected + "</li>")
            flash(message)
            # sheet = sh.add_worksheet(title=name + ' ' + month + '-' + day + '-' + year + ': ' + h + ":" + m + ":" + s, rows="100", cols="100")
        # #     print(sh.sheet1)
        # else:
        #     sh = client.create(ip)
        #     sh.share('patelshrey4201@gmail.com', perm_type='user', role='writer')

    # for titles in titles_list:
    #     if titles == ip:
    #
            # sh = client.open(ip)
            # ipIsThere = True
    if ipIsThere == False:
        message = Markup("<li>Download a file on Google Chrome or use the file uploader for this module to work</li>")
        flash(message)
    # print(oldhour)
    # print(oldmin)
    return render_template('users.html')
@app.route('/admin')
def admin():
    client = gspread.authorize(creds)
    q = 0
    counter = 0
    oldmin = 0
    oldhour = 0
    oldsec = 0
    dayCounter = 0
    # jsdata = request.form['javascript_data']
    # print(ipadd)
    # print(jsdata)
    ip = request.args.get('ip')
    sh = client.open(ip)
    for s in sh.worksheets():
        sheet = sh.get_worksheet(q)
        day = sheet.cell(1,2).value
        month = sheet.cell(1,3).value
        year = sheet.cell(1,4).value
        h = sheet.cell(1,5).value
        m = sheet.cell(1,6).value
        s = sheet.cell(1,7).value
        if int(datetime.datetime.now().strftime("%m")) - int(month) <= 1 and int(datetime.datetime.now().strftime("%d")) - int(day) <= 1 and int(datetime.datetime.now().strftime("%H")) - int(h) <= 24:
            counter += 1
            if int(datetime.datetime.now().strftime("%d")) - int(day) <= 1 and int(datetime.datetime.now().strftime("%H")) - int(h) <= 24:
                dayCounter += 1
            # print(counter)
            # print(oldhour)
            if int(h) >= oldhour and int(m) >= oldmin:
                # print(m)
                oldmin = int(m)
                oldhour = int(h)
                name = sheet.cell(1,1).value
                link = sheet.cell(1,8).value
                detected = sheet.cell(1,9).value
                total = sheet.cell(1,10).value
                # print(oldmin)
        q += 1
    message = Markup("<li>Statistics for IP Address: " + ip + "</li><li>Number Of Files Scanned in the past 24 Hours: " + str(dayCounter) + "</li><li>Number Of Files Scanned in the past Month: " + str(counter) + "</li><li>Last File Scanned: " + name + "</li><li>Number Of Antiviruses used: " + total + "</li><li>Number Of Antiviruses detecting Virus: " + detected + "</li>")
    flash(message)
    # print(oldhour)
    # print(oldmin)
    return render_template('admin.html')
@app.route('/streaming')
def streaming():
    return render_template('streaming.html')
@app.route('/mobileAdmin')
def mobileAdmin():
    return render_template('mobileAdmin.html')
@app.route('/mobile')
def mobile():
    return render_template('mobile.html')
@app.route('/mobileUsers')
def mobileUsers():
    return render_template('mobileUsers.html')
@app.route('/mobilescanresults')
def mobileScan():
    client = gspread.authorize(creds)
    q = 0
    # jsdata = request.form['javascript_data']
    # print(ipadd)
    # print(jsdata)
    ip = request.args.get('ip')
    ipIsThere = False
    for spreadsheet in client.openall():
        # print(spreadsheet.title)
        # titles_list.append(spreadsheet.title)
        if spreadsheet.title == ip:
        # #     # print(spreadsheet.title + " " + spreadsheet.id)
            # client.del_spreadsheet(spreadsheet.id)
            sh = client.open(ip)
            ipIsThere = True
    # sh = client.open(ip)
            for s in sh.worksheets():
                sheet = sh.get_worksheet(q)
                name = sheet.cell(1,1).value
                day = sheet.cell(1,2).value
                month = sheet.cell(1,3).value
                year = sheet.cell(1,4).value
                h = sheet.cell(1,5).value
                m = sheet.cell(1,6).value
                s = sheet.cell(1,7).value
                link = sheet.cell(1,8).value
                detected = sheet.cell(1,9).value
                total = sheet.cell(1,10).value
                message = Markup("<tr id='content'><td id='date'><a href='" + link + "'>" + month + "-" + day + "-" + year + "</a></td><td id='time'><a href='" + link + "'>" + h + ':' + m + ':' + s + "</a></td><td id='Name'><a href='" + link + "'>" + name + "</a></td></tr>")
                flash(message)
                # print('hi')
                q += 1
    if ipIsThere == False:
        message = Markup("<tr id='content'><td id='name'>No Files Downloaded yet</td></tr>")
        flash(message)
    return render_template('mobileScanResults.html')
    # @app.route('/')
# def upload():
#     return render_template('upload.html')

@app.route('/uploader', methods = ['GET', 'POST'])
def uploader():
    if request.method == 'POST':
        client = gspread.authorize(creds)
        f = request.files['file']
        f.save(f.filename)
        ip = request.args.get('ip')
        day = datetime.datetime.now().strftime("%d")
        month = datetime.datetime.now().strftime("%m")
        year = datetime.datetime.now().strftime("%y")
        h = datetime.datetime.now().strftime("%H")
        m = datetime.datetime.now().strftime("%M")
        s = datetime.datetime.now().strftime("%S")
        # print(date)
        # print(t)
        # print('Hi')
        params = {'apikey': apikey}
        files = {'file': (f.filename, open(f.filename, 'rb'))}
        response = requests.post(scanUrl, files=files, params=params)
        # print(response.json())
        resource = response.json()['resource']
        # print(resource)
        params = {'apikey': apikey, 'resource': resource}
        response = requests.get(reportUrl, params=params)
        # print(response.json())
        # sh = client.open(ip)
        # sh.share('patelshrey4201@gmail.com', perm_type='user', role='writer')
        # titles_list = []
        ipIsThere = False
        queue = "Your resource is queued for analysis"
        while response.json()['verbose_msg'] == queue:
            params = {'apikey': apikey, 'resource': resource}
            response = requests.get(reportUrl, params=params)
            time.sleep(25)
        if response.json()['verbose_msg'] != queue:
            for spreadsheet in client.openall():
                # print(spreadsheet.title)
                # titles_list.append(spreadsheet.title)
                if spreadsheet.title == ip:
                # #     # print(spreadsheet.title + " " + spreadsheet.id)
                    # client.del_spreadsheet(spreadsheet.id)
                    sh = client.open(ip)
                    ipIsThere = True
                    sheet = sh.add_worksheet(title=f.filename + ' ' + month + '-' + day + '-' + year + ': ' + h + ":" + m + ":" + s, rows="100", cols="100")
                # #     print(sh.sheet1)
                # else:
                #     sh = client.create(ip)
                #     sh.share('patelshrey4201@gmail.com', perm_type='user', role='writer')

            # for titles in titles_list:
            #     if titles == ip:
            #
                    # sh = client.open(ip)
                    # ipIsThere = True
            if ipIsThere == False:
                sh = client.create(ip)
                # sh.share('calebkremer09@gmail.com', perm_type='user', role='writer')
                # sh.share('patelshrey4201@gmail.com', perm_type='user', role='writer')
                sheet = sh.add_worksheet(title=f.filename + ' ' + month + '-' + day + '-' + year + ': ' + h + ':' + m + ':' + s, rows="100", cols="100")
                # sh.del_worksheet('Sheet1')
            # file = open("testfile.json","w")
            # file.write(repr(response.json()))
            # file.close()

            # total = str(response.json()['total'])
            link = response.json()['permalink']
            detected = response.json()['positives']
            tScans = response.json()['total']
            sheet.update_cell(1, 1, f.filename)
            sheet.update_cell(1, 2, day)
            sheet.update_cell(1, 3, month)
            sheet.update_cell(1, 4, year)
            sheet.update_cell(1, 5, h)
            sheet.update_cell(1, 6, m)
            sheet.update_cell(1, 7, s)
            sheet.update_cell(1, 8, link)
            sheet.update_cell(1, 9, detected)
            sheet.update_cell(1, 10, tScans)
            # response.json()['scans'][0][0]
            # print(response.json()['scans'][0]['detected'])
            z = 3
            y = 2
            w = 2
            # for a in response.json():
            #     if a == 'scans':
            #         sheet.update_cell(w,1,a)
            #         for x in response.json()[a]:
            #             # print(x)
            #             sheet.update_cell(z, 1, x)
            #             for i in response.json()[a][x]:
            #                 sheet.update_cell(z, y, i + ": ")
            #                 sheet.update_cell(z, y + 1, response.json()[a][x][i])
            #                 y += 2
            #             z += 1
            #             y = 2
            #             time.sleep(10)
            #         w = z + 1
            #     else:
            #         sheet.update_cell(w,1,a)
            #         sheet.update_cell(w,2,response.json(a))
            #         w += 1

                    # print(response.json()['scans'][x][i])
            # sheet = response.json()
            # stuff = sheet.get_all_records()
            # print(stuff)
            # print(response.json())
            # print(response.json()['permalink'])
            message = Markup("<p>Upload Completed. This page will automatically reload in a few moments to show the results of the scan.</p><script>window.location.href='/scanResults?ip=" + ip + "';</script>")
            flash(message)
        else:
            message = Markup("<div><p>Upload Completed! Come later for the scan results</p></div>")
        return render_template('uploadResults.html')

@app.route('/iotdatabase')
def iotdatabase():
    return render_template('iotdatabase.html')
@app.route('/mobileiotdatabase')
def mobileiotdatabase():
    return render_template('mobileIotDatabase.html')
@app.route('/userSelect')
def userSelect():
    for spreadsheet in client.openall():
        if spreadsheet.title != 'VulnData':
            message = Markup("<tr id='content'><td id='ipadd' name='" + spreadsheet.title + "' onclick='redir(this)'>" + spreadsheet.title + "</td></tr>")
            flash(message)
    return render_template('userSelect.html')
@app.route('/mobileUserSelect')
def mobileUserSelect():
    client = gspread.authorize(creds)
    for spreadsheet in client.openall():
        if spreadsheet.title != 'VulnData':
            message = Markup("<tr id='content'><td id='ipadd' name='" + spreadsheet.title + "' onclick='redir(this)'>" + spreadsheet.title + "</td></tr>")
            flash(message)
    return render_template('mobileUserSelect.html')
# @socketio.on('connect')
# def connect(sid, environ):
#     print(sid)
# @app.route('/postmethod', methods = ['POST'])
# def get_post_javascript_data():
#     global jsdata
#     jsdata = request.form['javascript_data']
#     return jsdata
# print(jsdata)
@app.route('/scanResults')
def scanResults():
    client = gspread.authorize(creds)
    q = 0
    # jsdata = request.form['javascript_data']
    # print(ipadd)
    # print(jsdata)
    ip = request.args.get('ip')
    ipIsThere = False
    for spreadsheet in client.openall():
        # print(spreadsheet.title)
        # titles_list.append(spreadsheet.title)
        if spreadsheet.title == ip:
        # #     # print(spreadsheet.title + " " + spreadsheet.id)
            # client.del_spreadsheet(spreadsheet.id)
            sh = client.open(ip)
            ipIsThere = True
    # sh = client.open(ip)
            for s in sh.worksheets():
                sheet = sh.get_worksheet(q)
                name = sheet.cell(1,1).value
                day = sheet.cell(1,2).value
                month = sheet.cell(1,3).value
                year = sheet.cell(1,4).value
                h = sheet.cell(1,5).value
                m = sheet.cell(1,6).value
                s = sheet.cell(1,7).value
                link = sheet.cell(1,8).value
                detected = sheet.cell(1,9).value
                total = sheet.cell(1,10).value
                message = Markup("<tr id='content'><td id='date'><a href='" + link + "'>" + month + "-" + day + "-" + year + "</a></td><td id='time'><a href='" + link + "'>" + h + ':' + m + ':' + s + "</a></td><td id='Name'><a href='" + link + "'>" + name + "</a></td><td id='total'><a href='" + link + "'>" + total + "</a></td><td id='detected'><a href='" + link + "'>" + detected + "</a></td></tr>")
                flash(message)
                # print('hi')
                q += 1
    if ipIsThere == False:
        message = Markup("<tr id='content'><td id='Name'>No Files Downloaded yet</td></tr>")
        flash(message)
    return render_template('scanResults.html')
@socketio.on( 'my event' )
def handle_my_custom_event( json ):
  print( 'recived my event: ' + str( json ) )
  socketio.emit( 'my response', json)

@socketio.on('url')
def handle_my_custom_event1(url, name, ip):
    client = gspread.authorize(creds)
    urllib.request.urlretrieve(url, name)
    # print(ip)
    # print(name)
    day = datetime.datetime.now().strftime("%d")
    month = datetime.datetime.now().strftime("%m")
    year = datetime.datetime.now().strftime("%y")
    h = datetime.datetime.now().strftime("%H")
    m = datetime.datetime.now().strftime("%M")
    s = datetime.datetime.now().strftime("%S")
    # print(date)
    # print(t)
    # print('Hi')
    params = {'apikey': apikey}
    files = {'file': (name, open(name, 'rb'))}
    response = requests.post(scanUrl, files=files, params=params)
    # print(response.json())
    resource = response.json()['resource']
    # print(resource)
    params = {'apikey': apikey, 'resource': resource}
    response = requests.get(reportUrl, params=params)
    # sh = client.open(ip)
    # sh.share('patelshrey4201@gmail.com', perm_type='user', role='writer')
    # titles_list = []
    ipIsThere = False
    queue = "Your resource is queued for analysis"
    while response.json()['verbose_msg'] == queue:
        params = {'apikey': apikey, 'resource': resource}
        response = requests.get(reportUrl, params=params)
        time.sleep(10)
    if response.json()['verbose_msg'] != queue:
        for spreadsheet in client.openall():
            # print(spreadsheet.title)
            # titles_list.append(spreadsheet.title)
            if spreadsheet.title == ip:
            # #     # print(spreadsheet.title + " " + spreadsheet.id)
                # client.del_spreadsheet(spreadsheet.id)
                sh = client.open(ip)
                ipIsThere = True
                sheet = sh.add_worksheet(title=name + ' ' + month + '-' + day + '-' + year + ': ' + h + ":" + m + ":" + s, rows="100", cols="100")
            # #     print(sh.sheet1)
            # else:
            #     sh = client.create(ip)
            #     sh.share('patelshrey4201@gmail.com', perm_type='user', role='writer')

        # for titles in titles_list:
        #     if titles == ip:
        #
                # sh = client.open(ip)
                # ipIsThere = True
        if ipIsThere == False:
            sh = client.create(ip)
            # sh.share('calebkremer09@gmail.com', perm_type='user', role='writer')
            # sh.share('patelshrey4201@gmail.com', perm_type='user', role='writer')
            sheet = sh.add_worksheet(title=name + ' ' + month + '-' + day + '-' + year + ': ' + h + ":" + m + ":" + s, rows="100", cols="100")
            sh.del_worksheet('Sheet1')
        # file = open("testfile.json","w")
        # file.write(repr(response.json()))
        # file.close()

        # total = str(response.json()['total'])
        link = response.json()['permalink']
        detected = response.json()['positives']
        tScans = response.json()['total']
        sheet.update_cell(1, 1, name)
        sheet.update_cell(1, 2, day)
        sheet.update_cell(1, 3, month)
        sheet.update_cell(1, 4, year)
        sheet.update_cell(1, 5, h)
        sheet.update_cell(1, 6, m)
        sheet.update_cell(1, 7, s)
        sheet.update_cell(1, 8, link)
        sheet.update_cell(1, 9, detected)
        sheet.update_cell(1, 10, tScans)
        # response.json()['scans'][0][0]
        # print(response.json()['scans'][0]['detected'])
        z = 3
        y = 2
        w = 2
        # for a in response.json():
        #     if a == 'scans':
        #         sheet.update_cell(w,1,a)
        #         for x in response.json()[a]:
        #             # print(x)
        #             sheet.update_cell(z, 1, x)
        #             for i in response.json()[a][x]:
        #                 sheet.update_cell(z, y, i + ": ")
        #                 sheet.update_cell(z, y + 1, response.json()[a][x][i])
        #                 y += 2
        #             z += 1
        #             y = 2
        #             time.sleep(10)
        #         w = z + 1
        #     else:
        #         sheet.update_cell(w,1,a)
        #         sheet.update_cell(w,2,response.json(a))
        #         w += 1

                # print(response.json()['scans'][x][i])
        # sheet = response.json()
        # stuff = sheet.get_all_records()
        # print(stuff)
        # print(response.json())
        # print(response.json()['permalink'])

def gen(VideoCamera):
    while True:
        frame = VideoCamera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n\r\n')

@app.route('/video_feed')
def video_feed():
    return Response(gen(VideoCamera()),
            mimetype='multipart/x-mixed-replace; boundary=frame')
@app.route('/ip_add')
def ip_add():
    server = socket.gethostbyname(socket.gethostname())
    return Response(server, mimetype='text/plain')

if __name__ == '__main__':
    app.run(host=serverIP, port="80", debug=True)
