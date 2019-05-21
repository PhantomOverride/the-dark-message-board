FROM python:3.7
ENV PYTHONUNBUFFERED 1
RUN useradd -u 1002 -ms /bin/bash dmb && pip install --upgrade pip
USER dmb
RUN mkdir /home/dmb/ctf
COPY --chown=dmb . /home/dmb/ctf/
WORKDIR /home/dmb/ctf
RUN pip install -r requirements.txt --user && echo "export PATH=$(python -c 'import site; print(site.USER_BASE + "/bin")'):$PATH" >> ~/.bashrc