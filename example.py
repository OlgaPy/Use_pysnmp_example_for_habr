#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import json
from sys import argv
from pysnmp.entity.rfc3413.oneliner import cmdgen
import logging

logging.basicConfig(
    level=logging.DEBUG, filename="./log.txt",
    format='%(asctime)s %(name)s.%(funcName)s +%(lineno)s: %(levelname)-8s [%(process)d] %(message)s',
)
logger = logging.getLogger("./log.txt")


class Device:

    def __init__(self, ipswitch, ro_community, oid_mt, port=161):
        self.ip = ipswitch
        self.ro = ro_community
        self.oid = oid_mt
        self.port = port
        self.if_oids = ['ifAdminStatus', 'ifOperStatus', 'ifInOctets', 'ifOutOctets']
        self.types_response = {'7': 'ifAdminStatus',
                               '8': 'ifOperStatus',
                               '10': 'ifInOctets',
                               '16': 'ifOutOctets'
                               }

        self.re_part = re.compile("(\d\.\d\.\d\.\d\.\d\.\d\.)(?P<part_mt>.*?)$", re.MULTILINE | re.DOTALL)
        self.part_mt_oid = self.re_part.search(self.oid).group('part_mt')
        self.re_mt = re.compile(f'\S+({self.part_mt_oid})\.(?P<port>\d{1, 2})\.(?P<sign>\d+)',
                                re.MULTILINE | re.DOTALL)
        self.re_if = re.compile("\S+\:\:\S+2\.2\.1\.(?P<key>\d+)\.(?P<port>\d{1,2})$",
                                re.MULTILINE | re.DOTALL)
        self.result = {}

    def get_ifwalk(self) -> dict:
        """
        Получение ответов коммутатора на ifAdminStatus, ifOperStatus, ifInOctets, ifOutOctets и переданный медиатайп.
        :return: self.result: dict
        """

        oids_form = [(oid_if,) for oid_if in self.if_oids]
        oids_form.extend((self.oid,))

        try:
            cmdGen = cmdgen.CommandGenerator()

            errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.nextCmd(
                cmdgen.CommunityData(self.ro, mpModel=1),
                cmdgen.UdpTransportTarget((self.ip, self.port)),
                *oids_form)

            if errorIndication:
                raise BaseException(f"errorIndication: {errorIndication}")
            if errorStatus:
                raise BaseException(f"errorStatus: "
                                    f"{errorStatus.prettyPrint(), errorIndex and varBindTable[-1][int(errorIndex) - 1] or '?'}")

            # если нет ошибок в полученном ответе - записываем все параметры в словарь
            for varBindTableRow in varBindTable:
                for name, val in varBindTableRow:

                    founds_mt_responce = self.re_mt.search(name.prettyPrint())
                    if founds_mt_responce is not None:
                        port = founds_mt_responce.group("port")
                        self.result.setdefault('sign', {})[port] = founds_mt_responce.group("sign")
                        self.result.setdefault('link', {})[port] = val.prettyPrint()

                    found_if_responce = self.re_if.search(name.prettyPrint())
                    if found_if_responce is not None:
                        port = found_if_responce.group('port')
                        type_response = self.types_response.get(found_if_responce.group('key'))
                        if (type_response in ['ifAdminStatus', 'ifOperStatus']) and (val.prettyPrint() == '1'):
                            status = 'up' if val.prettyPrint() == '1' else 'down'
                            self.result.setdefault(type_response, {})[port] = status
                            continue
                        self.result.setdefault(type_response, {})[port] = val.prettyPrint()


        except BaseException as bex:
            logger.error(bex)
        return self.result


if __name__ == "__main__":
    name_script, ip, ro, oid = argv
    device = Device(ip, ro, oid)
    print(json.dumps(device.get_ifwalk()))
