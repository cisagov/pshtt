FROM python:3.5-onbuild

ENTRYPOINT ["./entrypoint.sh"]
CMD ["--help"]
