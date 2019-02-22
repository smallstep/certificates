FROM python:alpine

RUN mkdir /src

ADD client.py /src
ADD client.requirements.txt /src
RUN pip3 install -r /src/client.requirements.txt

CMD ["python", "/src/client.py"]
