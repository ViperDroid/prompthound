# Intentionally vulnerable sample for demoing prompthound. DO NOT ship this.
import os
import pickle
import subprocess

import openai
import requests
import yaml

openai.api_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"  # PH001


def handle(request, cursor):
    user_q = request.args.get("q")
    prompt = f"You are a helpful bot. Answer the user: {request.args.get('q')}"  # PH007

    resp = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
    )
    answer = resp.choices[0].message.content

    eval(answer)                                   # PH002
    os.system(answer)                              # PH003
    subprocess.run(answer, shell=True)             # PH003
    cursor.execute(f"SELECT * FROM logs WHERE q = '{user_q}'")  # PH008
    obj = pickle.loads(answer.encode())            # PH012
    cfg = yaml.load(answer)                        # PH013
    print("full prompt:", prompt)                  # PH014
    requests.get("https://api.example.com", verify=False)  # PH010
    requests.get(answer)                           # PH016 (dynamic URL -> SSRF)
    html = render_template_string(answer)          # PH017 (SSTI)
    app.run(debug=True)                            # PH018
    aws_key = "AKIA1234567890ABCDEF"               # PH019
    dangerous = eval(user_q)  # prompthound: ignore  (demo: suppressed line)
    return obj, cfg, html

