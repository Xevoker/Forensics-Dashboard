<!-- This file contains the form for uploading evidence files to the system. It includes a dropdown to select the source program and a file input for selecting the evidence file. The form uses AJAX to submit the file without refreshing the page and displays a progress bar during the upload process. -->
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
// Js function to handle the file upload process using AJAX
function uploadFile() {
    // Check if a file is selected and it exists
    var fileInput = document.getElementById('evidence_file');
    if (fileInput.files.length === 0) {
        alert("Please select a file first.");
        return;
    }

    var formData = new FormData(document.getElementById('uploadForm'));
    var xhr = new XMLHttpRequest();
    
    document.getElementById('progressContainer').style.display = 'block';
    document.getElementById('uploadStatus').innerHTML = "Uploading...";

    // Progress bar update, calculates percentage done and displays it
    xhr.upload.addEventListener("progress", function(e) {
        if (e.lengthComputable) {
            var pc = Math.round((e.loaded / e.total) * 100);
            document.getElementById('progressBar').style.width = pc + "%";
            document.getElementById('progressBar').innerHTML = pc + "%";
        }
    });

    // Handle response from the server after upload is complete
    xhr.onreadystatechange = function() {
        if (xhr.readyState == 4) {
            if (xhr.status == 200) {
                document.getElementById('uploadStatus').innerHTML = "<div class='alert alert-success'>File uploaded successfully!</div>";
                // Refresh the page to show the new file has been added
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