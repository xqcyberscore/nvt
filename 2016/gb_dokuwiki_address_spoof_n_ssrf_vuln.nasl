###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_address_spoof_n_ssrf_vuln.nasl 6257 2017-05-31 14:33:17Z cfi $
#
# DokuWiki Password Reset Address Spoof And SSRF Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809084");
  script_version("$Revision: 6257 $");
  script_cve_id("CVE-2016-7964", "CVE-2016-7965");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-31 16:33:17 +0200 (Wed, 31 May 2017) $");
  script_tag(name:"creation_date", value:"2016-11-03 19:22:45 +0530 (Thu, 03 Nov 2016)");
  script_name("DokuWiki Password Reset Address Spoof And SSRF Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/1708");
  script_xref(name:"URL", value:"https://github.com/splitbrain/dokuwiki/issues/1709");

  script_tag(name:"summary", value:"The host is installed with DokuWiki and is
  prone to ssrf and password reset address spoof vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The sendRequest method in HTTPClient Class in file '/inc/HTTPClient.php' has 
    no way to restrict access to private networks when media file fetching is 
    enabled.

  - '$_SERVER[HTTP_HOST]' is used instead of the baseurl setting as part of the 
    password-reset URL.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct phishing attacks and to scan port of internal network.

  Impact Level: Application");  

  script_tag(name:"affected", value:"DokuWiki version 2016-06-26a and older.");

  script_tag(name:"solution", value:"The vendor sees this issue as a won't fix from
  DokuWiki side. Specific deployment hints to mitigate those vulnerabilities are available
  in the referenced github issues.");
  
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");
 
if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2016-06-26a" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Mitigation" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );