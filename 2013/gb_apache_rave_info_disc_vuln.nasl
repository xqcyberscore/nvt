###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_rave_info_disc_vuln.nasl 8200 2017-12-20 13:48:45Z cfischer $
#
# Apache Rave User Information Disclosure Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information about all user accounts via the offset parameter.
  Impact Level: Application";

tag_affected = "Apache Rave versions 0.11 to 0.20";
tag_insight = "The flaw is due to error in handling of User RPC API, returns the full user
  object, including the salted and hashed password.";
tag_solution = "Upgrade to Apache Rave 0.20.1 or later,
  For updates refer to http://rave.apache.org/downloads.html";
tag_summary = "The host is running Apache Rave and is prone to information
  disclosure vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803180";
CPE = "cpe:/a:apache:rave";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 8200 $");
  script_cve_id("CVE-2013-1814");
  script_bugtraq_id(58455);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 14:48:45 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-03-14 16:32:56 +0530 (Thu, 14 Mar 2013)");
  script_name("Apache Rave User Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/82758");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24744/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120769/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Mar/127");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/525982/30/0/threaded");

  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_dependencies("gb_apache_rave_detect.nasl");
  script_mandatory_keys("ApacheRave/installed");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

## Variables Initialization
vers = "";
port = 0;

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  port = 8080;
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get the application version
if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## check the vulnerable versions
if("unknown" >!< vers && (vers =~ "^0\."))
{
  if(version_in_range(version:vers, test_version:"0.11", test_version2:"0.20")){
    security_message(port);
  }
}
