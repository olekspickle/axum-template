// Project form handler
document.getElementById('project-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const id = form.querySelector('[name="id"]')?.value;

    if (!id) {
        alert('No ID found');
        return;
    }

    const res = await fetch(`/api/v1/projects/${id}`, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            title: form.title.value,
            slug: form.slug.value,
            description: form.description.value,
            category: form.category.value,
            thumbnail_url: form.thumbnail_url.value,
            images: form.images.value.split(',').map(s => s.trim()).filter(Boolean),
            tech_stack: form.tech_stack.value.split(',').map(s => s.trim()).filter(Boolean),
            demo_url: form.demo_url.value || null,
            repo_url: form.repo_url.value || null,
            featured: form.featured.checked,
        })
    });

    if (res.ok) {
        window.location.href = '/admin/projects';
    } else {
        alert('Failed to save project');
    }
});

// Post form handler
document.getElementById('post-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target;
    const id = form.querySelector('[name="id"]')?.value;

    if (!id) {
        alert('No ID found');
        return;
    }

    const res = await fetch(`/api/v1/posts/${id}`, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            title: form.title.value,
            slug: form.slug.value,
            content: form.content.value,
            excerpt: form.excerpt.value || form.content.value.substring(0, 200),
            cover_image: form.cover_image.value,
            tags: form.tags.value.split(',').map(s => s.trim()).filter(Boolean),
            author: form.author.value,
            published: form.published.checked,
        })
    });

    if (res.ok) {
        window.location.href = '/admin/posts';
    } else {
        alert('Failed to save post');
    }
});

// Delete handlers
async function deleteProject(id) {
    if (!confirm('Delete this project?')) return;
    const res = await fetch(`/api/v1/projects/${id}`, { method: 'DELETE' });
    if (res.ok) location.reload();
        else alert('Delete failed: ' + res.status);
}

async function deletePost(id) {
    if (!confirm('Delete this post?')) return;
    const res = await fetch(`/api/v1/posts/${id}`, { method: 'DELETE' });
    if (res.ok) location.reload();
        else alert('Delete failed: ' + res.status);
}

// Media upload handlers
const ALLOWED_EXTS = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'mp4', 'webm', 'mov', 'avi'];

function setupUpload(textareaId, statusId, getSlug) {
    const textarea = document.getElementById(textareaId);
    const status = document.getElementById(statusId);
    
    if (!textarea || !status) return;
    
    let fileCount = 0;
    
    function isVideo(ext) {
        return ['mp4', 'webm', 'mov', 'avi'].includes(ext);
    }
    
    function handleFiles(files, slug) {
        const allowedFiles = files.filter(file => {
            const ext = file.name.split('.').pop()?.toLowerCase();
            if (!ALLOWED_EXTS.includes(ext)) {
                status.textContent = `Skipped ${file.name}: unsupported type`;
                return false;
            }
            return true;
        });
        
        if (allowedFiles.length === 0) {
            status.textContent = 'No valid files to upload';
            return;
        }
        
        const processNext = async (index) => {
            if (index >= allowedFiles.length) {
                status.textContent = `Done: ${allowedFiles.length} file(s) uploaded`;
                return;
            }
            
            const file = allowedFiles[index];
            const ext = file.name.split('.').pop()?.toLowerCase();
            status.textContent = `Uploading ${index + 1}/${allowedFiles.length}...`;
            
            const formData = new FormData();
            formData.append('slug', slug);
            formData.append('file_count', fileCount + index);
            formData.append('file', file);
            
            try {
                const res = await fetch('/admin/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                
                const data = await res.json();
                if (data.success) {
                    let url, content;
                    if (data.existing && data.path) {
                        url = '/' + data.path;
                    } else {
                        url = `/static/media/${ext === 'gif' ? 'gif' : ext === 'webp' ? 'webp' : ext === 'avif' ? 'avif' : isVideo(ext) ? 'video' : 'img'}/${data.slug}-${data.file_count}.${ext}`;
                    }
                    if (isVideo(ext)) {
                        content = `<video controls loop muted playsinline class="w-full max-w-2xl rounded-lg"><source src="${url}" type="video/mp4"></video>`;
                    } else {
                        content = `![${file.name}](${url})`;
                    }
                    textarea.value += (textarea.value ? '\n' : '') + content;
                    if (!data.existing) {
                        fileCount = data.file_count + 1;
                    }
                    processNext(index + 1);
                } else {
                    status.textContent = 'Upload failed';
                }
            } catch (err) {
                console.error('Upload error:', err);
                status.textContent = `Upload failed: ${err}`;
            }
        };
        
        processNext(0);
    }
    
    // Paste handler
    textarea.addEventListener('paste', async (e) => {
        const items = e.clipboardData?.items;
        if (!items) return;
        
        const files = [];
        for (let i = 0; i < items.length; i++) {
            const item = items[i];
            if (item.kind === 'file') {
                const file = item.getAsFile();
                if (file) files.push(file);
            }
        }
        
        if (files.length === 0) return;
        
        const slug = getSlug();
        if (!slug) {
            status.textContent = 'Please enter a slug first';
            return;
        }
        
        handleFiles(files, slug);
    });
    
    // File input for button
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.multiple = true;
    fileInput.accept = ALLOWED_EXTS.map(e => '.' + e).join(',');
    fileInput.style.display = 'none';
    fileInput.addEventListener('change', () => {
        if (!fileInput.files?.length) return;
        const slug = getSlug();
        if (!slug) {
            status.textContent = 'Please enter a slug first';
            return;
        }
        handleFiles(Array.from(fileInput.files), slug);
        fileInput.value = '';
    });
    document.body.appendChild(fileInput);
    
    // Upload button
    const uploadBtn = document.createElement('button');
    uploadBtn.type = 'button';
    uploadBtn.textContent = '📎 Attach file';
    uploadBtn.className = 'ml-2 text-sm text-gray-500 hover:text-gray-700';
    uploadBtn.addEventListener('click', () => fileInput.click());
    status.after(uploadBtn);
}

const getPostSlug = () => document.getElementById('slug-input')?.value;
const getProjectSlug = () => document.getElementById('slug-input')?.value;

setupUpload('content-input', 'upload-status', getPostSlug);
setupUpload('description-input', 'upload-status', getProjectSlug);