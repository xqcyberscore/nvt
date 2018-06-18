###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_nt_ms03-007.nasl 10213 2018-06-15 10:04:26Z cfischer $
#
# Unchecked Buffer in ntdll.dll (Q815021)
#
# Authors:
# Trevor Hemsley, by using smb_nt_ms03-005.nasl
# from Michael Scheidell as a template.
#
# Copyright:
# Copyright (C) 2003 Trevor Hemsley
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.11413");
  script_version("$Revision: 10213 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 12:04:26 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(7116);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0109");
  script_xref(name:"IAVA", value:"2003-A-0005");
  script_name("Unchecked Buffer in ntdll.dll (Q815021)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Trevor Hemsley");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"The remote host is vulnerable to a flaw in ntdll.dll
  which may allow an attacker to gain system privileges, by exploiting it through, for
  instance, WebDAV in IIS5.0 (other services could be exploited, locally and/or remotely)");

  script_tag(name:"solution", value:"The vendor has released updates, please see http://www.microsoft.com/technet/security/bulletin/ms03-007.mspx
  or http://www.microsoft.com/technet/security/bulletin/MS03-013.mspx

  Note : Microsoft recommends (quoted from advisory) that:

  If you have not already applied the MS03-007 patch from this bulletin, Microsoft recommends you apply the MS03-013
  patch as it also corrects an additional vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, xp:2, win2k:4) <= 0 ) exit(0);

if ( hotfix_missing(name:"Q811493") > 0 &&
     hotfix_missing(name:"Q815021") > 0 &&
     hotfix_missing(name:"840987") > 0 )
{
  if ( hotfix_check_sp(xp:2) > 0 && hotfix_missing(name:"890859") <= 0 ) exit(0);
  security_message(port:0);
}
