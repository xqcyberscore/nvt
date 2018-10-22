###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_dt_rpath_insecure_lib_load_vuln.nasl 12010 2018-10-22 08:23:57Z mmartin $
#
# IBM DB2 'DT_RPATH' Insecure Library Loading Code Execution Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902489");
  script_version("$Revision: 12010 $");
  script_bugtraq_id(48514);
  script_cve_id("CVE-2011-4061");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:23:57 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-08 15:07:48 +0530 (Tue, 08 Nov 2011)");
  script_name("IBM DB2 'DT_RPATH' Insecure Library Loading Code Execution Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/518659");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/downloads.php?id=77");
  script_xref(name:"URL", value:"http://www.nth-dimension.org.uk/downloads.php?id=83");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/Remote/ver");
  script_tag(name:"impact", value:"Successful exploitation allows local unauthenticated users to
gain elevated privileges and execute arbitrary code with root privileges.");
  script_tag(name:"affected", value:"IBM DB2 version 9.7");
  script_tag(name:"insight", value:"The flaws are due to an error in 'db2rspgn' and 'kbbacf1', which
allow users to gain privileges via a Trojan horse libkbb.so in the current
working directory.");
  script_tag(name:"solution", value:"Upgrade to version 9.7 Fix Pack 6, 10.1 Fix Pack 1, or higher.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053");
  script_tag(name:"summary", value:"The host is running IBM DB2 and is prone to insecure library
loading vulnerabilities.");
  exit(0);
}


include("version_func.inc");

ibmVer = get_kb_item("IBM-DB2/Remote/ver");
if(!ibmVer){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 => 09000
  if(version_is_equal(version:ibmVer, test_version:"09000"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
