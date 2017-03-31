###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmailer_95328.nasl 5099 2017-01-25 11:00:33Z cfi $
#
# PHPMailer < 5.2.22 Local Information Disclosure Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:phpmailer:phpmailer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108051");
  script_version("$Revision: 5099 $");
  script_cve_id("CVE-2017-5223");
  script_bugtraq_id(95130);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N"); 
  script_tag(name:"last_modification", value:"$Date: 2017-01-25 12:00:33 +0100 (Wed, 25 Jan 2017) $");
  script_tag(name:"creation_date", value:"2017-01-25 11:00:00 +0100 (Wed, 25 Jan 2017)");
  script_name("PHPMailer < 5.2.22 Local Information Disclosure Vulnerability");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_phpmailer_detect.nasl");
  script_mandatory_keys("phpmailer/Installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95328");

  script_tag(name:"summary", value:"This host is running PHPMailer and is prone
  to a local information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists because PHPMailer's msgHTML method applies
  transformations to an HTML document to make it usable as an email message body. One of the
  transformations is to convert relative image URLs into attachments using a script-provided
  base directory. If no base directory is provided, it resolves to /, meaning that relative
  image URLs get treated as absolute local file paths and added as attachments. To form a
  remote vulnerability, the msgHTML method must be called, passed an unfiltered, user-supplied
  HTML document, and must not set a base directory.");
 
  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information
  that may aid in launching further attacks.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"PHPMailer versions 5.0.0 through 5.2.20 are vulnerable. ");

  script_tag(name:"solution", value:"Upgrade to PHPMailer 5.2.22 or later.
  For updates refer to https://github.com/PHPMailer/PHPMailer");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.0.0", test_version2:"5.2.20" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.22" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );