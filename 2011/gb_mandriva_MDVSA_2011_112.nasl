###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for blender MDVSA-2011:112 (blender)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Multiple vulnerabilities have been identified and fixed in blender:

  oggparsevorbis.c in FFmpeg 0.5 does not properly perform certain
  pointer arithmetic, which might allow remote attackers to obtain
  sensitive memory contents and cause a denial of service via a crafted
  file that triggers an out-of-bounds read. (CVE-2009-4632)
  
  vorbis_dec.c in FFmpeg 0.5 uses an assignment operator when a
  comparison operator was intended, which might allow remote attackers
  to cause a denial of service and possibly execute arbitrary code via
  a crafted file that modifies a loop counter and triggers a heap-based
  buffer overflow. (CVE-2009-4633)
  
  Multiple integer underflows in FFmpeg 0.5 allow remote attackers to
  cause a denial of service and possibly execute arbitrary code via a
  crafted file that (1) bypasses a validation check in vorbis_dec.c
  and triggers a wraparound of the stack pointer, or (2) access a
  pointer from out-of-bounds memory in mov.c, related to an elst tag
  that appears before a tag that creates a stream. (CVE-2009-4634)
  
  FFmpeg 0.5 allows remote attackers to cause a denial of service and
  possibly execute arbitrary code via a crafted MOV container with
  improperly ordered tags that cause (1) mov.c and (2) utils.c to use
  inconsistent codec types and identifiers, which causes the mp3 decoder
  to process a pointer for a video structure, leading to a stack-based
  buffer overflow. (CVE-2009-4635)
  
  FFmpeg 0.5 allows remote attackers to cause a denial of service (hang)
  via a crafted file that triggers an infinite loop. (CVE-2009-4636)
  
  The av_rescale_rnd function in the AVI demuxer in FFmpeg 0.5 allows
  remote attackers to cause a denial of service (crash) via a crafted
  AVI file that triggers a divide-by-zero error. (CVE-2009-4639)
  
  Array index error in vorbis_dec.c in FFmpeg 0.5 allows remote
  attackers to cause a denial of service and possibly execute arbitrary
  code via a crafted Vorbis file that triggers an out-of-bounds
  read. (CVE-2009-4640)
  
  flicvideo.c in libavcodec 0.6 and earlier in FFmpeg, as used in MPlayer
  and other products, allows remote attackers to execute arbitrary code
  via a crafted flic file, related to an arbitrary offset dereference
  vulnerability. (CVE-2010-3429)
  
  libavcodec/vorbis_dec.c in the Vorbis decoder in FFmpeg 0.6.1
  and earlier allows remote attackers to cause a denial of service
  (application crash) via a crafted .ogg file, related to the
  vorbis_floor0_decode function. (CVE-2010-4704)
  
  Fix invalid reads in VC-1 decoding (CVE-2011-0723)
  
  Packa ... 

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "blender on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2011-07/msg00002.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831424");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 14:44:51 +0200 (Fri, 22 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name: "MDVSA", value: "2011:112");
  script_cve_id("CVE-2009-4632", "CVE-2009-4633", "CVE-2009-4634", "CVE-2009-4635", "CVE-2009-4636", "CVE-2009-4639", "CVE-2009-4640", "CVE-2010-3429", "CVE-2010-4704", "CVE-2011-0723");
  script_name("Mandriva Update for blender MDVSA-2011:112 (blender)");

  script_tag(name:"summary", value:"Check for the Version of blender");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"blender", rpm:"blender~2.47~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
