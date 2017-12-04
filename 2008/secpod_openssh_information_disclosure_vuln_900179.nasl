##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openssh_information_disclosure_vuln_900179.nasl 7906 2017-11-24 12:59:24Z cfischer $
#
# OpenSSH CBC Mode Information Disclosure Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900179");
  script_version("$Revision: 7906 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 13:59:24 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_cve_id("CVE-2008-5161");
  script_bugtraq_id(32319);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_name("OpenSSH CBC Mode Information Disclosure Vulnerability");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32760/");
  script_xref(name:"URL", value:"http://www.cpni.gov.uk/Docs/Vulnerability_Advisory_SSH.txt");

  tag_impact = "Successful exploits will allow attackers to obtain four bytes of plaintext from
  an encrypted session.

  Impact Level: Application";

  tag_affected = "- SSH Communications Security Tectia Client and Server version 6.0.4 and prior

  - SSH Communications Security Tectia ConnectSecure version 6.0.4 and prior

  - OpenSSH version prior to 5.2";

  tag_insight = "The flaw is due to the improper handling of errors within an SSH session
  encrypted with a block cipher algorithm in the Cipher-Block Chaining 'CBC' mode.";

  tag_solution = "Upgrade to OpenSSH 5.2 or later

  http://www.openssh.com/portable.html";

  tag_summary = "The host is installed with OpenSSH and is prone to information
  disclosure vulnerability.

  This NVT has been replaced by NVT 'OpenSSH CBC Mode Information Disclosure Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.100153).";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); # Duplicated of 2009/openssh_32319_remote.nasl

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );