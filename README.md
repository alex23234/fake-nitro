# fake-nitro
ahem so this code will login into your account and it will replace a preset word with a gif
# installation
its simple firstly install `python` from the offical source and clone this repo via `git clone https://github.com/alex23234/fake-nitro.git`
you need to install git for this command however its optional,you can download zip via just click on code and press on download zip
after your in the cloned repo make a venv for linux its
```bash
python3 -m venv .venv
```
for windows its
```powershell
python -m venv .venv
```
i recommend you use uv for windows tho

to activate it for linux its
```bash
source .venv/bin/activate
```
for windows its
```powershell
.\.venv\Scripts\activate.ps1
```
btw windows might not let you run this,execution policy and all that use this command for this
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

then to install dependencies it should be the same for linux and windows i think i may be wrong
```bash
pip install -r requirerments.txt
```

this should install everything
now you can directly run 
```bash
python3 main.py
```
or to turn it into a binary you can use `pyinstaller`
info will be here
https://pypi.org/project/pyinstaller/
