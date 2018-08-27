###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edir_ncp_mem_crptn_vuln_lin.nasl 11125 2018-08-26 21:14:30Z cfischer $
#
# Novell eDirectory NCP Memory Corruption Vulnerability - (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800138");
  script_version("$Revision: 11125 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-26 23:14:30 +0200 (Sun, 26 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5038");
  script_bugtraq_id(31956);
  script_name("Novell eDirectory NCP Memory Corruption Vulnerability - (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32395");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46138");
  script_xref(name:"URL", value:"http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5037180.html");
  script_xref(name:"URL", value:"http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5037181.html");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to corrupt process memory,
  which will allow remote code execution on the target machines or can cause
  denial of service condition.

  Impact Level: Application");

  script_tag(name:"affected", value:"Novell eDirectory before 8.7.3 SP10 and 8.8 SP2 and prior on Linux.");

  script_tag(name:"insight", value:"The flaw is due to a use-after-free error in the NetWare Core
  Protocol(NCP) engine when handling 'Get NCP Extension Information by
  Name' Requests.");

  script_tag(name:"summary", value:"This host is running Novell eDirectory and is prone to Memory
  Corruption Vulnerability.");

  script_tag(name:"solution", value:"Upgrade to 8.7.3 SP10 FTF1 or 8.8 SP3, or
  Apply the available patch from below link,

  http://download.novell.com/Download?buildid=DwSGwHlu4pc~

  http://download.novell.com/Download?buildid=wxO984kvjmc~

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

eDirVer = get_bin_version( full_prog_name:"ndsd", version_argv:"--version", ver_pattern:"Novell eDirectory ([0-9.]+ (SP[0-9]+)?)", sock:sock );
ssh_close_connection();
if( ! eDirVer[1] ) exit( 0 );

eDirVer = ereg_replace( pattern:" ", string:eDirVer[1], replace:"." );
if( version_in_range( version:eDirVer, test_version:"8.8", test_version2:"8.8.SP2" ) ) {
  report = report_fixed_ver( installed_version:eDirVer, fixed_version:"8.8.SP3" );
  security_message( port:0, data:report );
  exit( 0 );
} else if( version_is_less( version:eDirVer, test_version:"8.7.3.SP10" ) ){
  report = report_fixed_ver( installed_version:eDirVer, fixed_version:"8.7.3.SP10" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );