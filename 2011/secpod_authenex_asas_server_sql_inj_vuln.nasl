###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_authenex_asas_server_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# ASAS Server End User Self Service (EUSS) SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_solution = "Apply the patc from below link,
  http://support.authenex.com/

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation will let attackers to authenex database, dump all
  the OTP tokens, users information including credentials.
  Impact Level: Application";
tag_affected = "Authenex ASAS version 3.1.0.3 and prior.";
tag_insight = "The flaw is due to an input passed to the 'rgstcode' parameter in
  'akeyActivationLogin.do', is not properly sanitised before being used in
  SQL queries.";
tag_summary = "The host is running Authenex ASAS and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902476");
  script_cve_id("CVE-2011-4801");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ASAS Server End User Self Service (EUSS) SQL Injection Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_require_ports("Services/www", 5080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/46103");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105287/authenex-sql.txt");
  script_xref(name : "URL" , value : "http://support.authenex.com/index.php?_m=downloads&_a=viewdownload&downloaditemid=125");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get the HTTP Port
asPort = get_http_port(default:5080);
if(!asPort){
  exit(0);
}

## Get request
sndReq = http_get(item:"/initial.do", port:asPort);
rcvRes = http_send_recv(port:asPort, data:sndReq);

## Confirm the application
if('ASAS Web Management Console Login' >< rcvRes)
{
  ## grep for the version
  asVer = eregmatch(pattern:"ASAS Web Management Console v([0-9.]+)",
                    string:rcvRes);

  if(!isnull(asVer[1]))
  {
    ## Check for version is less equal 3.1.0.3
    if(version_is_less_equal(version:asVer[1], test_version:"3.1.0.3")){
      security_message(asPort);
    }
  }
}
