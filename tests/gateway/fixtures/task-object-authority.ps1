function AssertTaskObjectAuthority($sd,[string]$owner,$parentSD){
 # Task Scheduler object-only authority. Filesystem/private-desktop checks are separate and unchanged.
 $trust=@($owner,'S-1-5-18','S-1-5-32-544')
 foreach($pair in @(@{value=$parentSD;folder=$true},@{value=$sd;folder=$false})){
  $value=$pair.value
  if($null -eq $value -or $null -eq $value.Owner -or $value.Owner.Value -ne $owner -or -not ([int]$value.ControlFlags -band 4) -or $null -eq $value.DiscretionaryAcl){throw 'Task object owner/non-null DACL refused'}
  if(([int]$value.ControlFlags -band (-bnot 36868)) -ne 0){throw 'Task object unexpected descriptor controls refused'}
  if($pair.folder -and -not ([int]$value.ControlFlags -band 4096)){throw 'Task parent folder protected DACL refused'}
  $full=@{};$principalRead=0
  foreach($entry in $value.DiscretionaryAcl){
   if($entry -isnot [Security.AccessControl.CommonAce] -or [int]$entry.AceType -ne 0 -or [int]$entry.AceFlags -ne 0 -or $entry.IsCallback){throw 'Task object ACE type/inheritance/condition refused'}
   $sid=$entry.SecurityIdentifier.Value;$mask=[int]$entry.AccessMask
   if($sid -notin $trust){throw 'Task object foreign trustee refused'}
   if(($pair.folder -and $mask -in @(268435456,2032127)) -or (-not $pair.folder -and $mask -eq 2032127)){
    if($full.ContainsKey($sid)){throw 'Task object duplicate full-control ACE refused'};$full[$sid]=$true
   }elseif(-not $pair.folder -and $sid -eq $owner -and $mask -eq 1179785 -and $principalRead -eq 0){$principalRead=1
   }else{throw 'Task object unexpected access mask/duplicate principal read refused'}
  }
  if($full.Count -ne 3 -or @($trust|Where-Object {-not $full.ContainsKey($_)}).Count -ne 0){throw 'Task object required full-control trustees absent'}
 }
 return @{scope='TaskScheduler-object';ownerSID=$owner;taskProtectedDACL=[bool]([int]$sd.ControlFlags -band 4096);folderProtectedDACL=$true;exactTrustedEffectiveACL=$true;noInheritedACE=$true;principalReadACE=$principalRead}
}
