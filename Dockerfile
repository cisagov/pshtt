FROM python:3.5.4

COPY . /
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["./entrypoint.sh"]
CMD ["--help"]
