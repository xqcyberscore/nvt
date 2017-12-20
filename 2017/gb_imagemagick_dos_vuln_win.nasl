###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_imagemagick_dos_vuln_win.nasl 8173 2017-12-19 11:45:56Z cfischer $
#
# ImageMagick coders/rle.c Denial of Service Vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:imagemagick:imagemagick";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107206");
  script_version("$Revision: 8173 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 12:45:56 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-05-23 19:30:51 +0200 (Tue, 23 May 2017)");
  script_cve_id("CVE-2017-9144");
  script_bugtraq_id(98603);

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"registry");
  script_name("ImageMagick coders/rle.c Denial of Service Vulnerability (Windows)");

  script_tag(name: "summary", value: "ImageMagick is prone to a denial-of-service vulnerability");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect NVT and check if the version is vulnerable or not.");
  
  script_tag(name: "impact" , value: "An attacker can exploit this issue to crash the affected application, resulting in denial-of-service conditions.");

  script_tag(name: "affected", value: "ImageMagick versions prior to 6.9.8-5 and 7.0.x prior to 7.0.5-6.");
  script_tag(name: "solution", value: "Updates are available. Please see the references or vendor advisory for more information.");

  script_xref(name: "URL" , value: "https://github.com/ImageMagick/ImageMagick/blob/master/ChangeLog");
  script_xref(name: "URL" , value: "https://github.com/ImageMagick/ImageMagick/blob/ImageMagick-6/ChangeLog");
  script_xref(name: "URL" , value: "https://github.com/ImageMagick/ImageMagick/commit/7fdf9ea808caa3c81a0eb42656e5fafc59084198");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");
  script_dependencies("secpod_imagemagick_detect_win.nasl");
  script_mandatory_keys("ImageMagick/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"6.9.8.5" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.5.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.9.8-5/7.0.5-6" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit ( 99 );

