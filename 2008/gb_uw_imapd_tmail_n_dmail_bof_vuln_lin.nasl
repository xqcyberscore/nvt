###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_uw_imapd_tmail_n_dmail_bof_vuln_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# UW-imapd tmail and dmail BOF Vulnerabilities (Linux)
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

tag_impact = "Successful exploitation allows execution of arbitrary code, but requires
  that the utilities are configured as a delivery backend for a mail transfer
  agent allowing overly long destination mailbox names.
  Impact Level: Application";
tag_affected = "University of Washington Alpine 2.00 and priror on Linux.
  University Of Washington's imapd Versions prior to 2007d on Linux.";
tag_insight = "The flaws are due to boundary error in the tmail/dmail utility,
  when processing overly long mailbox names composed of a username and '+'
  character followed by a long string and when specifying a long folder
  extension argument on the command line.";
tag_solution = "Update to Version 2007d.
  http://www.washington.edu/imap/
  http://www.washington.edu/alpine/tmailbug.html";
tag_summary = "The host has UW-imapd installed and is prone to Buffer Overflow
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800149");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-04 14:15:00 +0100 (Thu, 04 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5005");
  script_bugtraq_id(32072);
  script_name("UW-imapd tmail and dmail BOF Vulnerabilities (Linux)");
  script_xref(name : "URL" , value : "http://www.washington.edu/alpine/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32483");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

grep = find_bin(prog_name:"grep", sock:sock);
grep = chomp(grep[0]);

garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = string("[0-9]\\+[0-9]\\+[0-9]\\+[0-9]a\\?.*OK");

imapPath = find_file(file_name:"imapd", file_path:"/",
                     useregex:TRUE, regexpar:"$", sock:sock);

foreach imapBin (imapPath)
{
  imapBin = chomp(imapBin);
  if(islocalhost())
  {
    garg[4] = imapBin;
    arg = garg;
  }
  else
  {
    arg = garg[0] + " " + garg[1] + " " + garg[2] + " " +
          raw_string(0x22) + garg[3] + raw_string(0x22) + " " + imapBin;
  }

  imapVer = get_bin_version(full_prog_name:grep, version_argv:arg, sock:sock,
                            ver_pattern:"[0-9][0-9][0-9][0-9][a-z]?");
  if(imapVer[1] != NULL)
  {
    if(version_is_less(version:imapVer[1] ,test_version:"2007d")){
      security_message(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
