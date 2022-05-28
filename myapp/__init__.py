from flask import Flask,request,render_template
import sqlite3
import re
from datetime import datetime
app= Flask(__name__)
def logger(request):
	conn =sqlite3.connect('/usr/src/SQLite/New.db')
	tmp=""
	i=0
	for he in request.headers:
		if(i>5):
			tmp=tmp+" "+he[1]
		i=i+1
	method=request.method
	path=request.full_path
	body=request.get_data(as_text=True)
	dt=datetime.now()
	malicious=malcheck(body,path)
	conn.execute('''INSERT INTO TEST(REMOTE_ADDR,DATE_TIME,METHOD,PATH,HOST,USER_AGENT,ACCEPT,LANGUAGE,ENCODING,OTHER,BODY,SUSPICIOUS) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',(request.environ['REMOTE_ADDR'],dt,method,path,request.headers['Host'],request.headers['User-Agent'],request.headers['Accept'],request.headers['Accept-Language'],request.headers['Accept-Encoding'],tmp,body,malicious))
	conn.commit()
	conn.close()
def malcheck(str1,str2):
	sp_check=re.compile('[(|)|$|{|}|<|>|(|)|\|~|:|%7[B-E]|%5[B-D]|%3[A-C]|%3E|%2[2-6]]')
	if(sp_check.search(str1)!=None):
		return 1
	if(sp_check.search(str2)!=None):
		return 1
	return 0
@app.errorhandler(404)
def not_found(e):
  return render_template("404.html")
@app.route("/shezil",methods=['GET'])
def test():
		logger(request)
		return 'shezil'	
@app.route("/",methods=['GET'])
def home():
	logger(request)
	return render_template("form.html")
@app.route("/",methods=['POST'])
def check():
	logger(request)
	return request.form['Name']
if __name__=="__main__":
	app.run(host="0.0.0.0")
