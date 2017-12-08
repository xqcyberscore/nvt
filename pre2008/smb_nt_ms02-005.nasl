# OpenVAS Vulnerability Test
# $Id: smb_nt_ms02-005.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: IE 5.01 5.5 6.0 Cumulative patch (890923)
#
# Authors:
# Michael Scheidell <scheidell at secnap.net>
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-07-06
#  Updated the CVE, BID and Risk Factor
#
# Copyright:
# Copyright (C) 2002 Michael Scheidell
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
#

tag_summary = "The July 2004 Cumulative Patch for IE is not applied on the remote host.

Impact of vulnerability: Run code of attacker's choice. 

Recommendation: Customers using IE should install the patch immediately. 

See http://www.microsoft.com/technet/security/bulletin/ms05-020.mspx";

# Also supercedes MS02-005, MS02-047, MS02-027, MS02-023, MS02-015, MS01-015

if(description)
{
 script_id(10861);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-0842", "CVE-2004-0727", "CVE-2004-0216", "CVE-2004-0839",
               "CVE-2004-0844", "CVE-2004-0843", "CVE-2004-0841", "CVE-2004-0845",
               "CVE-2003-0814", "CVE-2003-0815", "CVE-2003-0816", "CVE-2003-0817",
               "CVE-2003-0823", "CVE-2004-0549", "CVE-2004-0566", "CVE-2003-1048",
               "CVE-2001-1325", "CVE-2001-0149", "CVE-2001-0727", "CVE-2001-0875",
               "CVE-2001-1325", "CVE-2001-0149", "CVE-2001-0727", "CVE-2001-0875",
               "CVE-2001-0339", "CVE-2001-0002", "CVE-2002-0190", "CVE-2002-0026",
               "CVE-2003-1326", "CVE-2002-0027", "CVE-2002-0022", "CVE-2003-1328",
               "CVE-2002-1262", "CVE-2002-0193", "CVE-1999-1016", "CVE-2003-0344",
               "CVE-2003-0233", "CVE-2003-0309", "CVE-2003-0113", "CVE-2003-0114",
               "CVE-2003-0115", "CVE-2003-0116", "CVE-2003-0531", "CVE-2003-0809",
               "CVE-2003-0530", "CVE-2003-1025", "CVE-2003-1026", "CVE-2003-1027",
               "CVE-2005-0554", "CVE-2005-0554", "CVE-2005-0555");
 script_bugtraq_id(11388, 11385, 11383, 11381, 11377, 11367, 11366, 10473, 8565, 
                   9009, 9012, 9013, 9014, 9015, 9182, 9663, 9798, 12477, 12475, 
                   12473, 12530, 13123, 13117, 13120);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_xref(name:"IAVA", value:"2003-A-0014");
 script_xref(name:"IAVA", value:"2004-A-0016");
 script_xref(name:"IAVA", value:"2005-A-0006");
 name = "IE 5.01 5.5 6.0 Cumulative patch (890923)";

 script_name(name);




 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");

 script_copyright("This script is Copyright (C) 2002 Michael Scheidell");
 family = "Windows : Microsoft Bulletins";
 script_family(family);

 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_mandatory_keys("SMB/WindowsVersion");

 script_require_ports(139, 445);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("secpod_reg.inc");

# 883939 superseedes MS05-020
if ( hotfix_missing(name:"883939.*") == 0 &&
     "883939" >!<  get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion") ) exit(0);

if ( hotfix_check_sp(nt:7, xp:3, win2k:5, win2003:1) <= 0 ) exit(0);

version = get_kb_item("SMB/WindowsVersion");
if(version)
{
 value = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version");
 if ( value )
  {
   minorversion = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion");
   report = string("The remote host is running IE Version ",value);
   if(minorversion)
   {
    if ( hotfix_missing(name:"890923.*") == 0 ) exit(0); 
    if ( "890923" >!< minorversion ) missing = "890923 (MS05-020)";
   }
   else if ( hotfix_missing(name:"890923.*") > 0 )
     missing = "890923 (MS05-020)";
   else exit(0);

   report += '\nHowever is it missing Microsoft Hotfix ' + missing + '\n';
   report += 'Solution: http://www.microsoft.com/technet/security/bulletin/ms05-020.mspx\nRisk Factor : High\n';

   if( missing ) security_message(port:get_kb_item("SMB/transport"), data:report);
  }
}
