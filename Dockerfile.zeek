FROM zeek/zeek:latest

COPY zeek_service.py /service/zeek_service.py
RUN useradd --create-home --uid 10002 zeekservice && chown -R zeekservice:zeekservice /service

USER zeekservice
WORKDIR /service
EXPOSE 8080
CMD ["python3", "zeek_service.py"]
