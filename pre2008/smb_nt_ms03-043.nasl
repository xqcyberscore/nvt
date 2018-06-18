###############################################################################
# OpenVAS Vulnerability Test
# $Id: smb_nt_ms03-043.nasl 10213 2018-06-15 10:04:26Z cfischer $
#
# Buffer Overrun in Messenger Service (828035)
#
# Authors:
# Jeff Adams <jeffrey.adams@hqda.army.mil>
#
# Copyright:
# Copyright (C) 2003 Jeff Adams
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
  script_oid("1.3.6.1.4.1.25623.1.0.11888");
  script_version("$Revision: 10213 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 12:04:26 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(8826);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0717");
  script_xref(name:"IAVA", value:"2003-B-0007");
  script_name("Buffer Overrun in Messenger Service (828035)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Jeff Adams");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"summary", value:"A security vulnerability exists in the Messenger Service that could allow
  arbitrary code execution on an affected system.

  This plugin determined by reading the remote registry that the patch MS03-043 has not been applied.");

  script_tag(name:"impact", value:"An attacker who successfully
  exploited this vulnerability could be able to run code with Local System
  privileges on an affected system, or could cause the Messenger Service to fail.
  Disabling the Messenger Service will prevent the possibility of attack.");

  script_tag(name:"solution", value:"The vendor has released updates, please see http://www.microsoft.com/technet/security/bulletin/ms03-043.mspx");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("secpod_reg.inc");

if ( hotfix_check_sp(nt:7, win2k:5, xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB828035") > 0  )
  security_message(port:0);
