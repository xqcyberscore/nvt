###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_glpi_sql_0_90_2.nasl 5782 2017-03-30 09:01:05Z teissa $
#
# GLPI 0.90.2 SQL Injection Vulnerability Detection
#
# Authors:
# Eissa Tameem <Tameem.Eissa@greenbone.net>

#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

tag_summary = "Detection of GLPI SQL Injection vulnerability.

The script  tells if the GLPI version is vulnerable to GLPI 0.90.2 SQL Injection exploit";


CPE ='cpe:/a:glpi-project:glpi';

if (description)
{

 script_oid("1.3.6.1.4.1.25623.1.0.107001");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_version("$Revision: 5782 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-30 11:01:05 +0200 (Thu, 30 Mar 2017) $");
 script_tag(name:"creation_date", value:"2016-05-10 14:43:29 +0200 (Tue, 10 May 2016)");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 script_name("GLPI 0.92.0 SQL Injection Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_glpi_detect.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("glpi/installed");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (! port = get_app_port( cpe:CPE)) exit(0);
if( vers = get_app_version( cpe:CPE, port:port ) )
{

 if (version_is_less(version:vers, test_version:"0.90.3"))
  {
      report = 'Installed version: ' + vers + '\nFixed version:     0.90.3';
      security_message( port:port, data:report );
      exit(0);
  }
}

exit( 0 );
