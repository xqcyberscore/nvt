###############################################################################
# OpenVAS Vulnerability Test
# $Id: linpha_34422.nasl 9782 2018-05-09 13:46:05Z cfischer $
#
# LinPHA 1.3.4 Multiple Cross-Site Scripting Vulnerabilities
#
# Authors
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:linpha:linpha";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100120");
 script_version("$Revision: 9782 $");
 script_cve_id("CVE-2014-7265");
 script_bugtraq_id(34422);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"last_modification", value:"$Date: 2018-05-09 15:46:05 +0200 (Wed, 09 May 2018) $");
 script_tag(name:"creation_date", value:"2009-04-10 19:06:18 +0200 (Fri, 10 Apr 2009)");
 script_name("LinPHA 1.3.4 Multiple Cross-Site Scripting Vulnerabilities");

 script_tag(name:"summary", value:"This host is installed with LinPHA
 and is prone to multiple cross-site scripting vulnerabilities.");

 script_tag(name:"vuldetect", value:"Get the installed version with
 the help of detect NVT and check the version is vulnerable or not.");

 script_tag(name:"insight", value:"The flaw exists due to LinPHA
 fails to properly sanitise user supplied input");

 script_tag(name:"impact", value:"Successful remote exploitation will
 let the attacker execute arbitrary code in the scope of the
 application. As a result the attacker may gain sensitive information
 and use it to redirect the user to any other malicious URL.

 Impact Level: Application");

 script_tag(name:"affected", value:"LinPHA 1.3.4 is vulnerable;other
 versions may also be affected");

 script_tag(name:"solution", value:"No solution or patch was made available
 for at least one year since disclosure of this vulnerability. Likely none
 will be provided anymore. General solution options are to upgrade to a
 newer release, disable respective features, remove the product or replace
 the product by another one.");

 script_tag(name:"solution_type", value:"WillNotFix");
 script_tag(name:"qod_type", value:"remote_banner");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34422");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_dependencies("linpha_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("linpha/installed");

 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!version = get_kb_item(string("www/", port, "/linpha")))exit(0);
if(!matches = eregmatch(string:version, pattern:"^(.+) under (/.*)$"))exit(0);

vers = matches[1];

if(!isnull(vers) && vers >!< "unknown")
{
  if(version_is_less_equal(version: vers, test_version: "1.3.4"))
  {
    security_message(port:port);
    exit(0);
  }
}
