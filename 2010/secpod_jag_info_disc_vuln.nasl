###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_jag_info_disc_vuln.nasl 8258 2017-12-29 07:28:57Z teissa $
#
# JAG (Just Another Guestbook) Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to download the backup
database and obtain sensitive information.

Impact Level: Application";
tag_affected = "JAG (Just Another Guestbook) version 1.14 and prior.";
tag_insight = "The flaw is caused by improper restrictions on the 'database.sql file'. By
sending a direct request, this can exploited to download the backup database.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "The host is running JAG and is prone to Information Disclosure
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900745");
  script_version("$Revision: 8258 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 08:28:57 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0665");
  script_name("JAG (Just Another Guestbook) Information Disclosure Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_dependencies("secpod_jag_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56228");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11406");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

jagPort = get_http_port(default:80);
if(!jagPort){
  exit(0);
}

jagVer = get_kb_item("www/" + jagPort + "/JAG");
if(isnull(jagVer)){
  exit(0);
}

jagVer = eregmatch(pattern:"^(.+) under (/.*)$", string:jagVer);
if(!safe_checks() && jagVer[2] != NULL)
{
  sndReq = http_get(item:string(jagVer[2], "/database.sql"), port:jagPort);
  rcvRes = http_send_recv(port:jagPort, data:sndReq);
  if(!isnull(rcvRes) && ("create table guestbook" >< rcvRes))
  {
    security_message(jagPort);
    exit(0);
  }
}

if(jagVer[1] != NULL)
{
  if(version_is_less_equal(version:jagVer[1], test_version:"1.14")){
    security_message(jagPort);
  }
}
