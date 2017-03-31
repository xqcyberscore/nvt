###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_saia_pcd_1_22.nasl 5390 2017-02-21 18:39:27Z mime $
#
# Saia PCD < 1.22 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103895");
 script_version ("$Revision: 5390 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Saia PCD < 1.22 Multiple Vulnerabilities");

 script_xref(name:"URL", value:"http://www.sbc-support.com/de/product-index/firmware-for-pcd-cosinus.html");
 script_xref(name:"URL", value:"http://www.heise.de/security/meldung/Kritische-Schwachstelle-in-hunderten-Industrieanlagen-1854385.html");
 script_xref(name:"URL", value:"http://www.heise.de/security/meldung/Verwundbare-Industrieanlagen-Fernsteuerbares-Gotteshaus-1902245.html");
 
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2014-01-28 11:22:01 +0100 (Tue, 28 Jan 2014)");
 script_summary("Check the firmware version");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("General");
 script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Saia_PCD/banner");
 script_require_ports("Services/www", 80);

 script_tag(name:"impact", value:"Exploiting these issue could allow an attacker to compromise the
 application, access or modify data.");
 script_tag(name:"vuldetect", value:"Check the firmware version.");
 script_tag(name:"insight", value:"The firmware of the remote Saia PCD is older then 1.22.x");
 script_tag(name:"solution", value:"Update firmware to 1.22.x");
 script_tag(name:"summary", value:"Saia PCD is prone to a vulnerability in the user authentication");
 script_tag(name:"affected", value:"Saia PCD with firmware < 1.22.x");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

port = get_http_port (default:80);

banner = get_http_banner (port:port);
if( "Server: Saia PCD" >!< banner ) exit (0);

fix = '1.22';
version = eregmatch (pattern:'Server: Saia PCD[^/]+/([0-9.]+)', string:banner);
if( isnull (version[1]) ) exit (0);

if( version_is_less (version:version[1], test_version:fix) )
{
    report = 'Installed Firmware: ' + version[1] + '\nFixed Firmware:     ' + fix + '.x';
    security_message (port:port, data:report);
    exit(0);
}

exit (99);

