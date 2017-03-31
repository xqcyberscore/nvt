###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tnftpd_csrf_vuln.nasl 4220 2016-10-05 15:43:56Z cfi $
#
# tnftpd 'ftp://' Cross-Site Request Forgery Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:luke_mewburn:tnftpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901006");
  script_version("$Revision: 4220 $");
  script_tag(name:"last_modification", value:"$Date: 2016-10-05 17:43:56 +0200 (Wed, 05 Oct 2016) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7016");
  script_name("tnftpd 'ftp://' Cross-Site Request Forgery Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("FTP");
  script_dependencies("secpod_tnftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("tnftpd/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/31958");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45534");
  script_xref(name:"URL", value:"http://freshmeat.net/projects/tnftpd/?branch_id=14355&release_id=285654");

  tag_impact = "Successful exploitation will let the attacker execute arbitrary code to
  perform CSRF attacks, Web cache poisoning, and other malicious activities.
  Impact Level: Application/Network";

  tag_affected = "NetBSD, tnftpd Version prior to 20080929";

  tag_insight = "The flaw is due to the application truncating an overly long FTP
  command and improperly interpreting the remainder string as a new FTP
  command. This can be exploited via unknown vectors, probably involving a
  crafted 'ftp://' link to a tnftpd server.";

  tag_solution = "Upgrade to tnftpd version 20080929 or later,
  ftp://ftp.netbsd.org/pub/NetBSD/misc/tnftp/";

  tag_summary = "The host is running tnftpd server and is prone to Cross-Site Request
  Forgery vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"20080929" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"20080929" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );