# OpenVAS Vulnerability Test
# $Id: clamav-CB-A08-0001.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: ClamAV < 0.93.1 vulnerability
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Slight modification by Vlatko Kosturjak - Kost <kost@linux.hr>
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
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

tag_summary = "The remote host is probably affected by the
  vulnerabilities described in CVE 2007-6335 CVE 2007-6336 CVE 2007-6337
  CVE-2008-0318 CVE-2008-1100 CVE-2008-1387 CVE-2008-2713

  Impact
  CVE 2008-2713
  libclamav/petite.c in ClamAV before 0.93.1 allows remote attackers to cause
  a denial of service via a crafted Petite file that triggers an out-of-bound
  read.
  CVE 2008-1387
  ClamAV before 0.93 allows remote attackers to cause a denial of service
  (CPU consumption) via a crafted ARJ archive, as demonstrated by the PROTOS
  GENOME test suite for Archive Formats.
  CVE 2008-1100
  Buffer overflow in the cli_scanpe function in libclamav (libclamav/pe.c)
  for ClamAV 0.92 and 0.92.1 allows remote attackers to execute arbitrary
  code via a crafted Upack PE file.
  CVE 2008-0318
  Integer overflow in the cli_scanpe function in libclamav in ClamAV before
  0.92.1, as used in clamd, allows remote attackers to cause a denial of
  service and possibly execute arbitrary code via a crafted Petite packed
  PE file, which triggers a heap-based buffer overflow.
  CVE 2007-6337
  Unspecified vulnerability in the bzip2 decompression algorithm in
  nsis/bzlib_private.h in ClamAV before 0.92 has unknown impact and remote
  attack vectors.
  CVE 2007-6336
  off-by-one error in ClamAV before 0.92 allows remote attackers to execute
  arbitrary code via a crafted MS-ZIP compressed CAB file.
  CVE 2007-6335
  Integer overflow in libclamav in ClamAV before 0.92 allows remote attackers
  to execute arbitrary code via a crafted MEW packed PE file, which triggers
  a heap-based buffer overflow.";

tag_solution = "All ClamAV users should upgrade to the latest version:";

# $Revision: 9349 $

if(description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.90000");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-02-29 23:43:58 +0100 (Fri, 29 Feb 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6335", "CVE-2007-6336", "CVE-2007-6337", "CVE-2008-0318", "CVE-2008-1100", "CVE-2008-1387", "CVE-2008-2713");
  script_name("ClamAV < 0.93.1 vulnerability");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  family = "General";
  script_family(family);
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

#
# The code starts here
#
include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

getPath = find_bin(prog_name:"clamscan", sock:sock);
foreach binaryFile (getPath)
{
  if( chomp(binaryFile) == "" ) continue;
  avVer = get_bin_version(full_prog_name:chomp(binaryFile), version_argv:"-V",
                          ver_pattern:"ClamAV ([0-9.]+)", sock:sock);
  if(avVer[1] != NULL)
  {
    # Check for < 0.93.1 version of ClamAV
    if(version_is_less(version:avVer[1], test_version:"0.93.1")){
      security_message(0);
    }
    ssh_close_connection();
    exit(0);
  }
}
ssh_close_connection();
