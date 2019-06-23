FROM python:3.7.3-slim as compile_image
RUN apt-get update
RUN apt-get install -y --no-install-recommends build-essential gcc

RUN python -m venv /opt/venv
# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt requirements.txt 
RUN pip3 install -r requirements.txt


FROM python:3.7.3-slim as deploy_image
COPY --from=compile_image /opt/venv /opt/venv
# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"

ADD ./gatekeeper /src
WORKDIR /src
ENTRYPOINT ["python3"]
CMD ["main.py"]
