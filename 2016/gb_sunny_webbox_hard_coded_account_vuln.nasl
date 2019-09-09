###############################################################################
# OpenVAS Vulnerability Test
#
# Sunny WebBox Hard-Coded Account Vulnerability
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

CPE = "cpe:/o:sma_solar_technology_ag:webbox_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808204");
  script_version("2019-09-06T14:17:49+0000");
  script_cve_id("CVE-2015-3964");
  script_bugtraq_id(76617);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2016-05-24 10:37:42 +0530 (Tue, 24 May 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Sunny WebBox Hard-Coded Account Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Sunny WebBox
  and is prone to Hard-Coded Account vulnerability");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP POST and
  check whether it is able to login or not.");

  script_tag(name:"insight", value:"The flaw is due to,
  it was possible to login with hard-coded passwords 'User:0000'
  or 'Installer:1111' that cannot be changed or disabled by a user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain full access to the system.");

  script_tag(name:"affected", value:"Sunny WebBox All versions.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://files.sma.de/dl/8584/Sicherheit-TEN103010.pdf");
  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-15-181-02A");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_sunny_webbox_remote_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("Sunny/WebBox/Installed");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!sunnyPort = get_app_port(cpe:CPE)) exit(0);
if(!get_app_location(port:sunnyPort, cpe:CPE)) exit(0);

## Create hard-coded account list
## http://files.sma.de/dl/8584/Sicherheit-TEN103010.pdf
credentials = make_list("User:0000", "Installer:1111");
url = "/culture/index.dml";

host = http_host_name(port:sunnyPort);

foreach credential(credentials)
{
  user_pass = split(credential, sep:":", keep:FALSE);

  user = chomp(user_pass[0]);
  pass = chomp(user_pass[1]);

  data = string("LangEN&" + "Userlevels=" + user + "&password=" + pass);
  len = strlen(data);

  req = 'POST /culture/login HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;
  res = http_keepalive_send_recv(port:sunnyPort, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && 'name="Sunny WebBox' >< res && 'Logout' >< res &&
     'name="My Plant' >< res &&
    ('title="Settings' >< res || 'title="Spot Values' >< res || 'title="Updates' >< res))
  {
    report = report_vuln_url(port:sunnyPort, url:"/culture/login");
    report = report + '\n\nIt was possible to login using the following credentials:\n\n' + user + ':' + pass + '\n';
    security_message(port:sunnyPort, data:report);
    exit(0);
  }
}

exit(99);
