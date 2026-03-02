<div class="card mb-4">
    <div class="card-header">
        <i class="fas fa-file-upload me-1"></i> Upload Evidence to Case: <strong><?php echo htmlspecialchars($_SESSION['case_id']); ?></strong>
    </div>
    <div class="card-body">
        <form id="uploadForm" enctype="multipart/form-data">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label class="small mb-1">Source Program</label>
                    <select name="source_program" class="form-select" required>
                        <option value="Wireshark">Wireshark (.csv)</option>
                        <option value="Autopsy">Autopsy</option>
                        <option value="Volatility">Volatility 3</option>
                        <option value="Guymager">Guymager</option>
                    </select>
                </div>
                <div class="col-md-6 mb-3">
                    <label class="small mb-1">Select File</label>
                    <input type="file" name="evidence_file" id="evidence_file" class="form-control" required>
                </div>
            </div>
            <button type="button" onclick="uploadFile()" class="btn btn-primary w-100">Upload Evidence</button>
        </form>

        <div class="progress mt-3" style="display:none; height: 25px;" id="progressContainer">
            <div id="progressBar" class="progress-bar progress-bar-striped progress-bar-animated bg-success" role="progressbar" style="width: 0%">0%</div>
        </div>
        <div id="uploadStatus" class="mt-2 text-center"></div>
    </div>
</div>

<script>
function uploadFile() {
    var fileInput = document.getElementById('evidence_file');
    if (fileInput.files.length === 0) {
        alert("Please select a file first.");
        return;
    }

    var formData = new FormData(document.getElementById('uploadForm'));
    var xhr = new XMLHttpRequest();
    
    document.getElementById('progressContainer').style.display = 'block';
    document.getElementById('uploadStatus').innerHTML = "Uploading...";

    xhr.upload.addEventListener("progress", function(e) {
        if (e.lengthComputable) {
            var pc = Math.round((e.loaded / e.total) * 100);
            document.getElementById('progressBar').style.width = pc + "%";
            document.getElementById('progressBar').innerHTML = pc + "%";
        }
    });

    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                document.getElementById('uploadStatus').innerHTML = "<div class='alert alert-success'>File uploaded successfully!</div>";
                // Optional: Refresh the page after 2 seconds to show new data
                setTimeout(() => { location.reload(); }, 2000);
            } else {
                document.getElementById('uploadStatus').innerHTML = "<div class='alert alert-danger'>Error: " + xhr.responseText + "</div>";
            }
        }
    };

    xhr.open("POST", "../includes/process_upload.php");
    xhr.send(formData);
}
</script>