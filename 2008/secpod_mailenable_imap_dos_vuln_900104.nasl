##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mailenable_imap_dos_vuln_900104.nasl 9122 2018-03-17 14:01:04Z cfischer $
#
# MailEnable IMAP Denial of Service Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900104");
  script_version("$Revision: 9122 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-17 15:01:04 +0100 (Sat, 17 Mar 2018) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3449");
  script_bugtraq_id(30498);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("MailEnable IMAP Denial of Service Vulnerability");
  script_dependencies("secpod_reg_enum.nasl", "find_service.nasl", "smtpserver_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445, "Services/imap", 143);

  script_xref(name:"URL", value:"http://www.mailenable.com/hotfix/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/31325");

  script_tag(name:"summary", value:"The host is running MailEnable Mail Server, which prone to Denial
  of Service vulnerability.");
  script_tag(name:"insight", value:"The flaw exists due to the load created when handling multiple IMAP connections
  to the same folder.");
  script_tag(name:"affected", value:"MailEnable Enterprise Edition 3.52 and Professional Edition 3.52
  and prior on Windows (all)");
  script_tag(name:"solution", value:"Apply Patch,
  http://www.mailenable.com/hotfix/ME-10042.EXE");
  script_tag(name:"impact", value:"Successful exploitation will potentially cause a service crash.

  Impact Level : Application");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("imap_func.inc");

if( ! get_kb_item( "SMB/WindowsVersion" ) ) exit( 0 );

port = get_imap_port( default:143 );

if( "IMAP4rev1" >!< get_imap_banner( port:port ) ) exit( 0 );

mailVer = registry_get_sz( key:"SOFTWARE\Mail Enable\Mail Enable",
                           item:"Professional Version" );

if( ! mailVer ) {
  mailVer = registry_get_sz( key:"SOFTWARE\Mail Enable\Mail Enable",
                             item:"Enterprise Version" );
  if( ! mailVer ) {
    exit( 0 );
  }
}

if( registry_key_exists( key:"SOFTWARE\Mail Enable\Mail Enable\Updates\ME-10042" ) ) exit( 0 );


if( egrep( pattern:"^([0-2]\..*|3\.([0-4]?[0-9]|5[0-2]))$", string:mailVer ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
