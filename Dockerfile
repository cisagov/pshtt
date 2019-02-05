FROM python:3

# Set up a workspace
ENV PSHTT_HOME=/home/pshtt
RUN mkdir ${PSHTT_HOME}

# Create an unprivileged user
RUN groupadd --system pshtt \
  && useradd --system --comment="pshtt user" --gid="pshtt" pshtt

# Install pshtt
COPY . ${PSHTT_HOME}
RUN chown -R pshtt:pshtt ${PSHTT_HOME}
RUN pip install --no-cache ${PSHTT_HOME}

# Prepare to run
WORKDIR ${PSHTT_HOME}
USER pshtt:pshtt
ENTRYPOINT ["pshtt"]
CMD ["--help"]
