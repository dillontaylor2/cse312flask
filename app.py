from flask import Flask, render_template

app = Flask(__name__)
@app.route('/')
def returnIndex():
    return render_template('index.html')
@app.route('/login')
def returnLogin():  # put application's code here
    return render_template('login.html')

@app.route('/register')
def returnRegister():
    return render_template('register.html')

@app.after_request
def noSniff(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    app.run()