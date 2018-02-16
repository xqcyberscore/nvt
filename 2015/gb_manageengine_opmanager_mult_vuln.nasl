###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_opmanager_mult_vuln.nasl 8820 2018-02-15 05:56:30Z ckuersteiner $
#
# ManageEngine OpManager Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806053");
  script_version("$Revision: 8820 $");
  script_cve_id("CVE-2015-7765", "CVE-2015-7766");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-15 06:56:30 +0100 (Thu, 15 Feb 2018) $");
  script_tag(name:"creation_date", value:"2015-09-16 11:10:46 +0530 (Wed, 16 Sep 2015)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_name("ManageEngine OpManager Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with ManageEngine OpManager and is prone to multiple
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and check whether it is able to login
with default credentials.");

  script_tag(name:"insight", value:"Multiple flaws are due to it was possible to login with default credentials:
IntegrationUser/plugin.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute SQL queries on
the backend PostgreSQL instance with administrator rights and access shell with SYSTEM privileges.

  Impact Level: Application");

  script_tag(name:"affected", value:"ManageEngine OpManager versions 11.6 and earlier.");

  script_tag(name: "solution" , value:"Install the patch from below link,
  https://support.zoho.com/portal/manageengine/helpcenter/articles/pgsql-submitquery-do-vulnerability");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "URL", value: "https://www.exploit-db.com/exploits/38174");
  script_xref(name: "URL", value: "https://packetstormsecurity.com/files/133596");
  script_xref(name: "URL", value: "http://seclists.org/fulldisclosure/2015/Sep/66");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_manage_engine_opmanager_detect.nasl");
  script_mandatory_keys("OpManager/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!opmngrPort = get_app_port(cpe:CPE))
  exit(0);

## Get host name or IP
host = http_host_name(port:opmngrPort);
if(!host){
  exit(0);
}

url = "jsp/Login.do";

postData = 'clienttype=html&isCookieADAuth=&domainName=NULL&authType=localUser'+
           'Login&webstart=&ScreenWidth=1295&ScreenHeight=637&loginFromCookie'+
           'Data=&userName=IntegrationUser&password=plugin&uname=';

len = strlen( postData );

## Try to login with default credentials
req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + OPENVAS_HTTP_USER_AGENT + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      postData;
res = http_keepalive_send_recv( port:opmngrPort, data:req, bodyonly:FALSE );

if( res =~ "HTTP/1.1 302" && "index.jsp" >< res )
{
  cookie = eregmatch( pattern:"JSESSIONID=([0-9a-zA-Z]+);", string:res );
  if(!cookie[1]){
    exit(0);
  }
  req = string("GET /apiclient/ember/index.jsp HTTP/1.1\r\n",
             "Host:",host,"\r\n",
             "Connection: Close\r\n",
             "Cookie: flashversionInstalled=11.2.202; JSESSIONID=",cookie[1],"\r\n\r\n");

  res = http_send_recv(port:opmngrPort, data:req, bodyonly:FALSE);

  ## Confirm whether login is successful
  if(productName = "OpManager" >< res && 'HomeDashboard' >< res && 'Logout.do' >< res)
  {
    security_message(port:opmngrPort);
    exit(0);
  }
}

exit(0);
