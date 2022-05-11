# kAFL Deployment

This directory contains the necessary tools to deploy `kAFL` either locally or remotely, via `Ansible`.

## Requirements

- `python3`
- `python3-venv`

## Setup

~~~
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
~~~

## Deploy

~~~
(venv) $ ansible-playbook -i 'localhost,' -c local site.yml
~~~