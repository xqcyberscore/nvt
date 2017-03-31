###############################################################################
# OpenVAS Vulnerability Test
# $Id: putty_logon_credential_leak.nasl 5340 2017-02-18 16:45:14Z cfi $
#
# PuTTY SSH2 authentication password persistence weakness
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

#  Ref: Knud Erik Højgaard <knud@skodliv.dk>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14263");
  script_version("$Revision: 5340 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-18 17:45:14 +0100 (Sat, 18 Feb 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6724);
  script_cve_id("CVE-2003-0048");
  script_xref(name:"OSVDB", value:"7687");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("PuTTY SSH2 authentication password persistence weakness");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Windows");
  script_require_ports(139, 445);
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution", value:"Upgrade to the newest version of PuTTY");
  script_tag(name:"summary", value:"PuTTY is a free SSH client.

  It has been reported that this version does not safely handle password information. 
  As a result, a local user may be able to recover authentication passwords.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc"); 

path = registry_get_sz(item:"DisplayName",
       key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PuTTY_is1");

if(!path){
  exit(0);
}

puttyVer = ereg_replace(pattern:"(.* version) ([0-9.]+.*)", replace:"\1", string:path);
log_message(data:"ver " + puttyVer);
if(!puttyVer){
  exit(0);
}

if(version_is_less_equal(version:puttyVer, test_version:"0.54a")){
  security_message(0);
}
