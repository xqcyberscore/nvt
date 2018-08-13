###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avtech_avc787_dvr_default_cred_vuln.nasl 10887 2018-08-10 12:05:12Z santu $
#
# AVTech AVC 787 DVR Web Interface Default Credentials Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/o:avtech:avc7xx_dvr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813818");
  script_version("$Revision: 10887 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:05:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-08-07 12:34:02 +0530 (Tue, 07 Aug 2018)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("AVTech AVC 787 DVR Web Interface Default Credentials Vulnerability");

  script_tag(name:"summary", value:"This host is running AVTech AVC 787 DVR
  device and is prone to default credentials vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted data via 'HTTP POST' request
  and check whether it is able to login or not.");

  script_tag(name:"insight", value:"The flaw is due to an existence of hard
  coded credentials.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to bypass authentication and launch further attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"AVTech AVC 787 DVR device");

  script_tag(name:"solution", value:"No known solution is available as of 07th August, 2018.
  Information regarding this issue will be updated once solution details are available.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name:"URL", value:"http://www.avtech.hk/english/products5_1_787.htm");
  script_xref(name:"URL", value:"http://www.praetorianprefect.com/2009/12/shodan-cracking-ip-surveillance-dvr");
  script_xref(name:"URL", value:"http://www.smartvisiondirect.com/doc/avtech_avc_series_security_dvr_networking_howto_guide.pdf");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_dependencies("gb_avtech_avc7xx_dvr_device_detect.nasl");
  script_mandatory_keys("AVTech/AVC7xx/DVR/Device/Detected");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

avPort = get_app_port(cpe:CPE);
if(!avPort){
  exit(0);
}

if(!dir = get_app_location(cpe: CPE, port: avPort)) exit(0);

url = dir + "home.htm";
postData = "username=admin&password=admin&Submit=Submit";

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", get_host_ip(), "\r\n\r\n",
              postData);
buf = http_keepalive_send_recv(port:avPort, data:req);

if(buf =~ "HTTP/1.. 200 OK" && 'Server: AVTECH-WEBCAM' >< buf &&
   buf =~ "<title>.*Video Web Server.*</title>" && 'Next Channel' >< buf &&
  "Change Quality" >< buf && "Change Resolution" >< buf)
{
  report = 'It was possible to log directly into the AVTech AVC 787 DVR device' +
           ' with the following credentials:\n\nUsername: admin\nPassword: admin';
  security_message(port:avPort, data:report);
  exit(0);
}
exit(0);
